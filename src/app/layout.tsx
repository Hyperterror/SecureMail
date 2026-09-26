import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecureMailScope — Passive Email Cryptographic Forensics",
  description:
    "Upload PCAP captures and analyze email security: TLS versions, cipher suites, certificates, and anomaly detection.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
