package supervisorserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const knownGeneration = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const unknownGeneration = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type stubBackend struct {
	mu sync.Mutex
	restored []string
	observed []string
	restoreError error
	observeError error
	healthy bool
}

func (b *stubBackend) RestoreKnownGood(_ context.Context, ref string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.restored = append(b.restored, ref)
	return b.restoreError
}

func (b *stubBackend) ObserveKnownGood(_ context.Context, ref string) (bool,error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.observed = append(b.observed, ref)
	return b.healthy, b.observeError
}

func (b *stubBackend) counts() (int,int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.restored),len(b.observed)
}

type wireReply struct {
	Version int `json:"version"`
	Operation string `json:"operation"`
	Reference string `json:"reference"`
	OK bool `json:"ok"`
	Healthy bool `json:"healthy"`
}

func serverTestConfig(t *testing.T, backend *stubBackend) (Config, *Server) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "root")
	if err:=os.Mkdir(dir,0o700);err!=nil {t.Fatal(err)}
	cfg:=Config{
		SocketPath:filepath.Join(dir,"s.sock"),
		WatchdogUID:uint32(os.Geteuid()),
		WatchdogGID:uint32(os.Getegid()),
		AllowedGenerations:map[string]bool{knownGeneration:true},
	}
	server,err:=newServer(cfg,backend,uint32(os.Geteuid()))
	if err!=nil {t.Fatal(err)}
	return cfg,server
}

func startTestServer(t *testing.T, cfg Config, server *Server) string {
	t.Helper()
	ctx,cancel:=context.WithCancel(context.Background())
	done:=make(chan error,1)
	go func(){done<-server.Serve(ctx)}()
	t.Cleanup(func(){
		cancel()
		select {
		case err:=<-done:
			if err!=nil {t.Errorf("server shutdown: %v",err)}
		case <-time.After(2*time.Second):
			t.Error("server did not exit after cancellation")
		}
	})
	for i:=0;i<100;i++{
		if info,err:=os.Lstat(cfg.SocketPath);err==nil && info.Mode()&os.ModeSocket!=0 {return cfg.SocketPath}
		select{
		case err:=<-done:
			t.Fatalf("server failed before socket creation: %v",err)
		case <-time.After(5*time.Millisecond):
		}
	}
	t.Fatal("root server never bound local Unix socket")
	return ""
}

func rpcRaw(t *testing.T,socket string,payload string) ([]byte,error) {
	t.Helper()
	conn,err:=net.DialTimeout("unix",socket,time.Second)
	if err!=nil {return nil,err}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _,err:=io.WriteString(conn,payload);err!=nil{return nil,err}
	return io.ReadAll(io.LimitReader(bufio.NewReader(conn),4096))
}

func rpcJSON(t *testing.T,socket,operation,reference string) (wireReply,error) {
	t.Helper()
	payload:=`{"version":1,"operation":"`+operation+`","reference":"`+reference+`"}`+"\n"
	data,err:=rpcRaw(t,socket,payload)
	if err!=nil {return wireReply{},err}
	var reply wireReply
	if err:=json.Unmarshal(data,&reply);err!=nil{return wireReply{},err}
	return reply,nil
}

func TestRootSupervisorAuthenticatedFixedVerbRoundTrip(t *testing.T) {
	backend:=&stubBackend{healthy:true}
	cfg,srv:=serverTestConfig(t,backend)
	socket:=startTestServer(t,cfg,srv)
	restore,err:=rpcJSON(t,socket,"restore-known-good",knownGeneration)
	if err!=nil || !restore.OK || restore.Healthy || restore.Operation!="restore-known-good" ||
		restore.Reference!=knownGeneration || restore.Version!=1 {
		t.Fatalf("root server did not acknowledge exact restore verb: %+v %v",restore,err)
	}
	observe,err:=rpcJSON(t,socket,"observe-known-good",knownGeneration)
	if err!=nil || !observe.OK || !observe.Healthy || observe.Operation!="observe-known-good" ||
		observe.Reference!=knownGeneration || observe.Version!=1 {
		t.Fatalf("root server did not echo observed healthy generation: %+v %v",observe,err)
	}
	if a,b:=backend.counts();a!=1||b!=1 {
		t.Fatalf("not exactly one fixed privileged invocation per request: %d %d",a,b)
	}
}

func TestRootSupervisorRejectsUnknownGenerationOrArbitraryOperationBeforeBackend(t *testing.T){
	backend:=&stubBackend{healthy:true}
	cfg,srv:=serverTestConfig(t,backend)
	socket:=startTestServer(t,cfg,srv)
	for _,request:=range []string{
		`{"version":1,"operation":"restore-known-good","reference":"`+unknownGeneration+`"}`+"\n",
		`{"version":1,"operation":"exec-shell","reference":"`+knownGeneration+`"}`+"\n",
		`{"version":1,"operation":"restore-known-good","reference":"../../etc/shadow"}`+"\n",
		`{"version":2,"operation":"observe-known-good","reference":"`+knownGeneration+`"}`+"\n",
	} {
		data,err:=rpcRaw(t,socket,request)
		if err==nil {
			var reply wireReply
			if json.Unmarshal(data,&reply)==nil && reply.OK {
				t.Fatalf("untrusted root invocation was accepted: %s",request)
			}
		}
	}
	if a,b:=backend.counts();a!=0||b!=0 {t.Fatalf("untrusted commands reached backend: %d %d",a,b)}
}

func TestRootSupervisorRejectsUntrustedPeerUID(t *testing.T) {
	backend:=&stubBackend{healthy:true}
	cfg,_:=serverTestConfig(t,backend)
	cfg.WatchdogUID++
	srv,err:=newServer(cfg,backend,uint32(os.Geteuid()))
	if err!=nil {t.Fatal(err)}
	socket:=startTestServer(t,cfg,srv)
	data,err:=rpcRaw(t,socket,`{"version":1,"operation":"restore-known-good","reference":"`+knownGeneration+`"}`+"\n")
	if err==nil {
		var reply wireReply
		if json.Unmarshal(data,&reply)==nil && reply.OK {
			t.Fatal("unauthorized Unix peer executed root restore")
		}
	}
	if a,b:=backend.counts();a!=0||b!=0 {t.Fatal("unexpected root-side operation for untrusted peer")}
}

func TestRootSupervisorStrictlyBoundsFramingAndRejectsDuplicateOrUnknownKeys(t *testing.T){
	backend:=&stubBackend{healthy:true}
	cfg,srv:=serverTestConfig(t,backend)
	socket:=startTestServer(t,cfg,srv)
	for _,payload:=range []string{
		`{"version":1,"operation":"restore-known-good","reference":"`+knownGeneration+`","operation":"restore-known-good"}`+"\n",
		`{"version":1,"operation":"restore-known-good","reference":"`+knownGeneration+`","command":"id"}`+"\n",
		`{"version":1,"operation":"restore-known-good","reference":"`+knownGeneration+`"} {"another":1}`+"\n",
		`{"version":1,"operation":{"nested":"restore-known-good"},"reference":"`+knownGeneration+`"}`+"\n",
		strings.Repeat(" ",8192)+"\n",
		"not-json
",
	} {
		data,err:=rpcRaw(t,socket,payload)
		if err==nil {
			var reply wireReply
			if json.Unmarshal(data,&reply)==nil&&reply.OK {t.Fatal("malformed input reached privileged backend")}
		}
	}
	if a,b:=backend.counts();a!=0||b!=0 {t.Fatal("unsafe framing invoked privileged backend")}
}

func TestRootSupervisorDoesNotReportHealthyOnBackendFailure(t *testing.T) {
	backend:=&stubBackend{healthy:false,restoreError:errors.New("secret runtime diagnostics"),observeError:errors.New("readiness not observed")}
	cfg,srv:=serverTestConfig(t,backend)
	socket:=startTestServer(t,cfg,srv)
	for _,verb:=range []string{"restore-known-good","observe-known-good"} {
		data,err:=rpcRaw(t,socket,`{"version":1,"operation":"`+verb+`","reference":"`+knownGeneration+`"}`+"\n")
		if err!=nil{t.Fatal(err)}
		if strings.Contains(string(data),"secret runtime diagnostics")||strings.Contains(string(data),"readiness not observed") {
			t.Fatal("privileged runtime diagnostics leaked to unprivileged client")
		}
		var reply wireReply
		if err:=json.Unmarshal(data,&reply);err!=nil {t.Fatal(err)}
		if reply.OK||reply.Healthy {t.Fatalf("backend failure presented as successful root health: %+v",reply)}
	}
}

func TestRootSupervisorRejectsWorldWritableRootDirectoryAndSocketReplacement(t *testing.T) {
	backend:=&stubBackend{}
	cfg,_:=serverTestConfig(t,backend)
	if err:=os.Chmod(filepath.Dir(cfg.SocketPath),0o777);err!=nil{t.Fatal(err)}
	if _,err:=newServer(cfg,backend,uint32(os.Geteuid()));err==nil {
		t.Fatal("untrusted parent directory authorized root service")
	}
	if err:=os.Chmod(filepath.Dir(cfg.SocketPath),0o700);err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(cfg.SocketPath,[]byte("squatter"),0o600);err!=nil{t.Fatal(err)}
	srv,err:=newServer(cfg,backend,uint32(os.Geteuid()))
	if err!=nil{t.Fatal(err)}
	if err:=srv.Serve(context.Background());err==nil {
		t.Fatal("root supervisor overwrote or unlinked preexisting socket path")
	}
	raw,err:=os.ReadFile(cfg.SocketPath)
	if err!=nil||string(raw)!="squatter"{t.Fatalf("root service destroyed preexisting path: %v",err)}
}

func TestRootSupervisorRejectsMissingBackendOrInvalidAllowlist(t *testing.T) {
	backend:=&stubBackend{}
	cfg,_:=serverTestConfig(t,backend)
	if _,err:=newServer(cfg,nil,uint32(os.Geteuid()));err==nil {t.Fatal("nil backend is unsafe")}
	cfg.AllowedGenerations=nil
	if _,err:=newServer(cfg,backend,uint32(os.Geteuid()));err==nil {t.Fatal("unprovisioned generation list accepted")}
	cfg.AllowedGenerations=map[string]bool{"../../etc/shadow":true}
	if _,err:=newServer(cfg,backend,uint32(os.Geteuid()));err==nil {t.Fatal("arbitrary file path generation accepted")}
}
