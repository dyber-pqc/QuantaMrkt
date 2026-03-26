export const SITE = {
  name: 'QuantaMrkt',
  tagline: 'The Quantum-Safe AI Marketplace',
  description:
    'PQC-native infrastructure to secure AI models, agents, and codebases against quantum threats.',
  url: 'https://quantmrkt.com',
  github: 'https://github.com/dyber-pqc/QuantaMrkt',
};

export const NAV_ITEMS = [
  { label: 'Models', href: '/models' },
  { label: 'Agents', href: '/agents' },
  { label: 'Explore', href: '/explore' },
  { label: 'Download', href: '/download' },
  { label: 'Docs', href: '/docs' },
  { label: 'Dashboard', href: '/dashboard' },
] as const;

export const DASHBOARD_NAV = [
  { label: 'Overview', href: '/dashboard', icon: 'grid' },
  { label: 'Your Models', href: '/dashboard/models', icon: 'box' },
  { label: 'Agents', href: '/dashboard/agents', icon: 'bot' },
  { label: 'Migrate', href: '/dashboard/migrate', icon: 'arrow-right-left' },
  { label: 'Compliance', href: '/dashboard/compliance', icon: 'shield-check' },
  { label: 'Marketplace', href: '/models', icon: 'store' },
  { label: 'Settings', href: '/dashboard/settings', icon: 'settings' },
] as const;

export const PRICING_TIERS = [
  {
    name: 'Free',
    price: '$0',
    period: 'forever',
    description: 'Get started with quantum-safe verification.',
    features: [
      '50 verifications/month',
      'Basic HNDL analysis',
      'Public model signatures',
      'Community support',
    ],
    cta: 'Get Started',
    highlighted: false,
  },
  {
    name: 'Pro',
    price: '$99',
    period: '/month',
    description: 'Full access for individual developers and researchers.',
    features: [
      'Unlimited verifications',
      'Full Migrator access',
      'API access',
      'Agent identity (5 agents)',
      'Priority support',
    ],
    cta: 'Start Free Trial',
    highlighted: true,
  },
  {
    name: 'Team',
    price: '$299',
    period: '/month',
    description: 'Collaboration tools for security teams.',
    features: [
      'Everything in Pro',
      '5 team seats',
      'CI/CD integration',
      'Compliance dashboard',
      'Agent identity (25 agents)',
    ],
    cta: 'Start Free Trial',
    highlighted: false,
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    period: '',
    description: 'Dedicated infrastructure and support.',
    features: [
      'Everything in Team',
      'Unlimited seats',
      'On-prem deployment',
      'SLA guarantee',
      'Dedicated support',
      'Custom integrations',
    ],
    cta: 'Contact Sales',
    highlighted: false,
  },
] as const;
