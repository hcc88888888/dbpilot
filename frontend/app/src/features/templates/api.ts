import type { DefaultApi } from '../../../../generated/api/dist/index.js';
import { useGeneratedApiClient } from '../../api/client';

export function useTemplatesApi(override?: DefaultApi): DefaultApi {
  return useGeneratedApiClient(override);
}
