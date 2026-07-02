import globalDomainsJson from './global-domains.json';

export interface GlobalEquivalentDomain {
  type: number;
  domains: string[];
  excluded: boolean;
}

/** Bitwarden global equivalent-domains dataset (from vaultwarden src/static/global_domains.json). */
export const GLOBAL_EQUIVALENT_DOMAINS = globalDomainsJson as GlobalEquivalentDomain[];
