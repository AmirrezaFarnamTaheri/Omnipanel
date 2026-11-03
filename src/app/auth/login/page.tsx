import { redirect } from "next/navigation";
import { requirePage } from "@/lib/auth";

export default async function LoginPage() {
  const me = await requirePage("viewer");
  if (me) redirect("/");
  return null;
}

export async function GET() {
  return new Response(
    `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in to OmniPanel</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #1f2937;
    }
    .card {
      background: #ffffff;
      border-radius: 16px;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
      padding: 40px;
      width: 100%;
      max-width: 420px;
    }
    .brand {
      font-size: 1.5rem;
      font-weight: 700;
      letter-spacing: -0.025em;
      color: #111827;
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 24px;
    }
    .brand .icon { font-size: 2rem; }
    h2 {
      font-size: 1.25rem;
      font-weight: 600;
      margin-bottom: 8px;
      color: #111827;
    }
    p.subtitle {
      font-size: 0.875rem;
      color: #6b7280;
      margin-bottom: 24px;
    }
    .form-group { margin-bottom: 16px; }
    label {
      display: block;
      font-size: 0.875rem;
      font-weight: 500;
      margin-bottom: 6px;
      color: #374151;
    }
    input {
      width: 100%;
      padding: 10px 14px;
      border: 1px solid #d1d5db;
      border-radius: 8px;
      font-size: 1rem;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input:focus {
      border-color: #4f46e5;
      box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
    }
    .btn {
      width: 100%;
      padding: 12px;
      background: #4f46e5;
      color: #ffffff;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      margin-top: 8px;
      transition: background 0.2s;
    }
    .btn:hover { background: #4338ca; }
    .btn:active { transform: translateY(1px); }
    .divider {
      display: flex;
      align-items: center;
      gap: 12px;
      margin: 24px 0;
      font-size: 0.75rem;
      color: #9ca3af;
    }
    .divider::before, .divider::after { content: ""; flex: 1; border-bottom: 1px solid #e5e7eb; }
    .demo {
      font-size: 0.8125rem;
      color: #6b7280;
      line-height: 1.5;
      margin-top: 16px;
      padding-top: 16px;
      border-top: 1px solid #f3f4f6;
    }
    .demo strong { color: #1f2937; }
    .demo a { color: #4f46e5; text-decoration: none; font-weight: 500; }
    .demo a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand">
      <span class="icon">🔺</span>
      <span>OmniPanel</span>
    </div>
    <h2>Sign in</h2>
    <p class="subtitle">Enter your email to receive a one-time sign-in link.</p>
    <form method="POST" action="/api/auth/login">
      <div class="form-group">
        <label for="email">Email address</label>
        <input type="email" id="email" name="email" required placeholder="admin@example.com" autocomplete="email">
      </div>
      <button type="submit" class="btn">Send magic link</button>
    </form>
    <div class="demo">
      <strong>Demo credentials:</strong><br>
      Email: <code>owner@example.com</code> · Password: <code>owner123</code><br>
      Email: <code>operator@example.com</code> · Password: <code>operator123</code><br>
      Email: <code>viewer@example.com</code> · Password: <code>viewer123</code><br>
      <br>
      New to OmniPanel? <a href="/setup">Run first-time setup</a>
    </div>
  </div>
</body>
</html>`,
    { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } }
  );
}

export async function POST(req: Request) {
  const formData = await req.formData();
  const email = String(formData.get("email") ?? "");
  return new Response(
    `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign-in link sent - OmniPanel</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #10b981 0%, #059669 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #1f2937;
    }
    .card {
      background: #ffffff;
      border-radius: 16px;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
      padding: 48px 40px;
      width: 100%;
      max-width: 420px;
      text-align: center;
    }
    .icon { font-size: 3rem; margin-bottom: 16px; }
    h2 {
      font-size: 1.5rem;
      font-weight: 700;
      color: #111827;
      margin-bottom: 8px;
    }
    p {
      font-size: 1rem;
      color: #6b7280;
      margin-bottom: 24px;
    }
    .code {
      display: inline-block;
      margin: 16px 0;
      padding: 12px 24px;
      background: #f3f4f6;
      border-radius: 8px;
      font-family: monospace;
      font-size: 1.125rem;
      color: #111827;
      border: 1px solid #e5e7eb;
    }
    .btn {
      display: inline-block;
      padding: 12px 32px;
      background: #4f46e5;
      color: #ffffff;
      border-radius: 8px;
      font-weight: 600;
      text-decoration: none;
      transition: background 0.2s;
    }
    .btn:hover { background: #4338ca; }
    .back {
      display: inline-block;
      margin-top: 16px;
      font-size: 0.875rem;
      color: #4f46e5;
      text-decoration: none;
    }
    .back:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✅</div>
    <h2>Magic link sent</h2>
    <p>A one-time sign-in link has been sent to <strong>${email}</strong>.</p>
    <div class="code">${email}</div>
    <a href="/" class="btn">Go to dashboard</a>
    <div><a href="/auth/login" class="back">← Sign in with another email</a></div>
  </div>
</body>
</html>`,
    { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } }
  );
}
