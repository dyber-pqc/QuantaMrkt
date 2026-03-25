export interface User {
  id: string;
  email: string;
  name: string;
  tier: 'free' | 'pro' | 'team' | 'enterprise';
}

export function getSessionFromCookie(cookieHeader: string | null): User | null {
  if (!cookieHeader) return null;

  // TODO: Implement actual session parsing from encrypted cookie
  // For now, return a mock user for development
  return {
    id: 'usr_mock_001',
    email: 'dev@quantmrkt.com',
    name: 'Developer',
    tier: 'free',
  };
}
