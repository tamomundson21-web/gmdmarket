export default function Home() {
  return (
    <main
      style={{
        minHeight: '100dvh',
        display: 'grid',
        placeItems: 'center',
        fontFamily: 'system-ui, sans-serif',
        background: '#0b0f16',
        color: '#e6edf3',
      }}
    >
      <div style={{ textAlign: 'center' }}>
        <h1 style={{ fontSize: '2.5rem', margin: 0, letterSpacing: '-0.02em' }}>
          GMD Market
        </h1>
        <p style={{ color: '#8b98a5', marginTop: '0.5rem' }}>
          Global Menkul Değerler
        </p>
        <p style={{ color: '#4d5b68', marginTop: '2rem', fontSize: '0.875rem' }}>
          İskelet kuruldu. F1 geliştirme fazı henüz başlamadı.
        </p>
      </div>
    </main>
  );
}