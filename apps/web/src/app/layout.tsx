import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'GMD Market',
  description: 'Global Menkul Değerler — USD paper trading / CFD simülasyonu',
  manifest: '/manifest.webmanifest',
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="tr">
      <body style={{ margin: 0 }}>{children}</body>
    </html>
  );
}