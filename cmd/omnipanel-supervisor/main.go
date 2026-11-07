// Command omnipanel-supervisor runs the restricted root-owned rollback
// endpoint for the separately supervised non-root node watchdog.
// It never accepts raw configs, service names or host commands over IPC.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/supervisorserver"
)

const maxRootProvisioningBytes = 64 << 10

var (
	errRootProvisioning = errors.New("root supervisor requires owner-only local configuration and canonical trust")
	supervisorRefPattern = regexp.MustCompile("^sha256:[a-f0-9]{64}$")
	supervisorDigestPattern = regexp.MustCompile("^[a-f0-9]{64}$")
)

type provisioning struct {
	SocketPath string
	WatchdogUID uint32
	WatchdogGID uint32
	AllowedGenerations []string
	Native supervisorserver.NativeConfig
}

func absoluteSafe(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		strings.IndexByte(path,0) < 0
}

func (p provisioning) validate() error {
	if p.WatchdogUID==0 || p.WatchdogGID==0 ||
		!absoluteSafe(p.SocketPath) || len(p.SocketPath)>=108 ||
		!absoluteSafe(p.Native.GenerationDirectory) ||
		!absoluteSafe(p.Native.ActiveConfigPath) ||
		filepath.Base(p.Native.ActiveConfigPath)!="active.json" ||
		!absoluteSafe(p.Native.SingBoxBinary) ||
		!absoluteSafe(p.Native.SystemctlBinary) ||
		!supervisorDigestPattern.MatchString(p.Native.SingBoxBinaryDigest) ||
		!supervisorDigestPattern.MatchString(p.Native.SystemctlBinaryDigest) ||
		len(p.AllowedGenerations)==0 || len(p.AllowedGenerations)>32 {
		return errRootProvisioning
	}
	host,portText,err:=net.SplitHostPort(p.Native.HealthAddress)
	port,portErr:=strconv.Atoi(portText)
	if err!=nil || portErr!=nil || host!="127.0.0.1" || port<=0 || port>65535 {
		return errRootProvisioning
	}
	seen:=map[string]bool{}
	for _,ref:=range p.AllowedGenerations {
		if !supervisorRefPattern.MatchString(ref) || seen[ref] {
			return errRootProvisioning
		}
		seen[ref]=true
	}
	return nil
}

// rejectRepeatedKeys walks the entire JSON tree before ordinary typed
// decoding. Go's decoder normally permits duplicate keys and folded aliases;
// those are ambiguous and forbidden for locally pinned root trust policy.
func rejectRepeatedKeys(raw []byte) error {
	decoder:=json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk=func(depth int) error {
		if depth>32 {return errRootProvisioning}
		token,err:=decoder.Token()
		if err!=nil {return errRootProvisioning}
		delim,ok:=token.(json.Delim)
		if !ok {return nil}
		switch delim {
		case '{':
			keys:=map[string]bool{}
			for decoder.More() {
				tok,err:=decoder.Token()
				key,ok:=tok.(string)
				if err!=nil || !ok {return errRootProvisioning}
				folded:=strings.ToLower(key)
				if keys[folded] {return errRootProvisioning}
				keys[folded]=true
				if err:=walk(depth+1);err!=nil{return err}
			}
			end,err:=decoder.Token()
			if err!=nil || end!=json.Delim('}') {return errRootProvisioning}
		case '[':
			for decoder.More() {
				if err:=walk(depth+1);err!=nil{return err}
			}
			end,err:=decoder.Token()
			if err!=nil || end!=json.Delim(']') {return errRootProvisioning}
		default:
			return errRootProvisioning
		}
		return nil
	}
	if err:=walk(0);err!=nil{return err}
	if _,err:=decoder.Token();!errors.Is(err,io.EOF){return errRootProvisioning}
	return nil
}

// loadProvisioningForTesting uses exactly the same file/JSON validation as
// production, substituting only the expected file-owner UID in unprivileged
// tests. The public loadProvisioning path always requires UID 0.
func loadProvisioningForTesting(path string, ownerUID uint32) (provisioning,error) {
	if os.Geteuid()!=int(ownerUID) || !absoluteSafe(path) {
		return provisioning{},errRootProvisioning
	}
	parent,err:=os.Lstat(filepath.Dir(path))
	if err!=nil || !parent.IsDir() || parent.Mode().Perm()&0o077!=0 {
		return provisioning{},errRootProvisioning
	}
	owner,ok:=parent.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid!=ownerUID {return provisioning{},errRootProvisioning}
	fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,0)
	if err!=nil{return provisioning{},errRootProvisioning}
	file:=os.NewFile(uintptr(fd),path)
	defer file.Close()
	info,err:=file.Stat()
	if err!=nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077!=0 ||
		info.Size()<=0 || info.Size()>maxRootProvisioningBytes {
		return provisioning{},errRootProvisioning
	}
	fileOwner,ok:=info.Sys().(*syscall.Stat_t)
	if !ok || fileOwner.Uid!=ownerUID{return provisioning{},errRootProvisioning}
	raw,err:=io.ReadAll(io.LimitReader(file,maxRootProvisioningBytes+1))
	if err!=nil || len(raw)==0 || len(raw)>maxRootProvisioningBytes ||
		int64(len(raw))!=info.Size(){return provisioning{},errRootProvisioning}
	if err:=rejectRepeatedKeys(raw);err!=nil{return provisioning{},err}
	decoder:=json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var p provisioning
	if err:=decoder.Decode(&p);err!=nil{return provisioning{},errRootProvisioning}
	var extra any
	if err:=decoder.Decode(&extra);!errors.Is(err,io.EOF){return provisioning{},errRootProvisioning}
	if err:=p.validate();err!=nil{return provisioning{},err}
	return p,nil
}

func loadProvisioning(path string) (provisioning,error) {
	if os.Geteuid()!=0{return provisioning{},errRootProvisioning}
	return loadProvisioningForTesting(path,0)
}

func run(ctx context.Context, cfg provisioning) error {
	if os.Geteuid()!=0 || ctx==nil {
		return errRootProvisioning
	}
	if err:=cfg.validate();err!=nil{return err}
	allowed:=make(map[string]bool,len(cfg.AllowedGenerations))
	for _,ref:=range cfg.AllowedGenerations{allowed[ref]=true}
	// Both constructors perform their own root-only validation and pin
	// generation and executable identity independently of any IPC request.
	backend,err:=supervisorserver.NewNativeBackend(cfg.Native,allowed)
	if err!=nil{return err}
	server,err:=supervisorserver.New(supervisorserver.Config{
		SocketPath:cfg.SocketPath,
		WatchdogUID:cfg.WatchdogUID,
		WatchdogGID:cfg.WatchdogGID,
		AllowedGenerations:allowed,
	},backend)
	if err!=nil{return err}
	return server.Serve(ctx)
}

func main(){
	var path string
	flag.StringVar(&path,"config","","absolute path to root-owned 0600 supervisor provisioning JSON")
	flag.Parse()
	if path=="" || flag.NArg()!=0{log.Fatal("root supervisor requires --config and no positional arguments")}
	cfg,err:=loadProvisioning(path)
	if err!=nil{log.Fatalf("root supervisor trust configuration refused: %v",err)}
	ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
	defer stop()
	if err:=run(ctx,cfg);err!=nil{log.Fatalf("root supervisor cannot start: %v",err)}
}
