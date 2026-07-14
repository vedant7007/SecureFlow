import { NextResponse } from 'next/server';
import { ratelimit } from '@/lib/ratelimit';
import { getClientIp } from '@/lib/client-ip';
import authConfig from "./auth.config";
import NextAuth from "next-auth";

const { auth } = NextAuth(authConfig);

export default auth(async (req) => {
  const token = req.auth;

  if (req.nextUrl.pathname.startsWith('/api/og') && ratelimit) {
    const ip = getClientIp(req.headers);
    const { success } = await ratelimit.limit(ip);

    if (!success) {
      return new NextResponse('Too Many Requests', { status: 429 });
    }
  }

  // RBAC Admin Route Guarding
  if (req.nextUrl.pathname.startsWith('/admin')) {
    const roles = (token?.user?.roles as string[]) || [];
    if (!token || !roles.includes("ADMIN")) {
      return NextResponse.redirect(new URL('/', req.nextUrl));
    }
  }

  return NextResponse.next();
});

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
