import type { ReactNode } from "react";
import { AuthProvider } from "../components/auth/AuthProvider";

import "./globals.css";

export const metadata = {
  title: "PhishHunter",
  description: "Phishing analysis workspace for SOC teams",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="vi">
      <body><AuthProvider>{children}</AuthProvider></body>
    </html>
  );
}
