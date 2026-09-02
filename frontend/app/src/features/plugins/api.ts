import type { DefaultApi } from '../../../../generated/api/dist/index.js';
import { useGeneratedApiClient } from '../../api/client';

export function usePluginsApi(override?: DefaultApi): DefaultApi {
  return useGeneratedApiClient(override);
}
