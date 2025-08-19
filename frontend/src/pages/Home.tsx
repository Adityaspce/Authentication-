
import { Button } from '@/components/ui/button';

export function HomePage() {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen">
      <h1 className="text-4xl font-bold mb-4">Welcome to the Certificate Verification Platform</h1>
      <p className="text-lg text-gray-600 mb-8">Securely issue and verify certificates on Solana.</p>
      <Button>Connect Phantom Wallet</Button>
    </div>
  );
}