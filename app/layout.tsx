import type {Metadata} from 'next';
import {Plus_Jakarta_Sans, JetBrains_Mono} from 'next/font/google';
import './globals.css';

const plusJakarta = Plus_Jakarta_Sans({
  subsets: ['latin'],
  variable: '--font-sans',
  weight: ['400', '500', '600', '700'],
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  weight: ['400', '500', '600'],
});

export const metadata: Metadata = {
  title: 'Adaptive BurstCDN',
  description:
    'Self-optimizing browser-side peer-assisted delivery layer with per-chunk source scheduling, SHA-256 verification, circuit breakers, and reproducible flash-crowd benchmarks.',
  openGraph: {
    title: 'Adaptive BurstCDN',
    description:
      'Self-optimizing browser-side peer-assisted delivery layer with per-chunk source scheduling, SHA-256 verification, circuit breakers, and reproducible flash-crowd benchmarks.',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Adaptive BurstCDN',
    description:
      'Self-optimizing browser-side peer-assisted delivery layer with per-chunk source scheduling, SHA-256 verification, circuit breakers, and reproducible flash-crowd benchmarks.',
  },
};

export default function RootLayout({children}: {children: React.ReactNode}) {
  return (
    <html lang="en" className={`${plusJakarta.variable} ${jetbrainsMono.variable} dark`}>
      <body
        suppressHydrationWarning
        className="bg-[#0B0F17] text-slate-100 antialiased selection:bg-sky-500/30 selection:text-sky-200 font-sans"
      >
        {children}
      </body>
    </html>
  );
}
