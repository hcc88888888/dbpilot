export type {
  AcceptDiscoveryCandidateRequest,
  DiscoveryCandidate,
  DiscoveryCandidateStatus,
  DiscoverySource,
} from '../../../../generated/api/dist/index.js';

export type DiscoveryFilters = {
  source?: import('../../../../generated/api/dist/index.js').DiscoverySource;
  status?: import('../../../../generated/api/dist/index.js').DiscoveryCandidateStatus;
  databaseFamily?: string;
};
