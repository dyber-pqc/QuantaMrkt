/// <reference path="../.astro/types.d.ts" />

import type { User } from './lib/auth';

declare namespace App {
  interface Locals {
    user?: User;
    runtime: {
      env: {
        GITHUB_CLIENT_ID: string;
        GITHUB_CLIENT_SECRET: string;
        SESSION_SECRET: string;
      };
    };
  }
}
