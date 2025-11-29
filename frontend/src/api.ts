// API client for ACPG backend

import type { 
  PolicyRule, 
  AnalysisResult, 
  AdjudicationResult,
  EnforceResponse,
  ViolationSummary,
  Violation,
  ProofBundle
} from './types';

const API_BASE = '/api/v1';

async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  if (!response.ok) {
    let errorDetail = `HTTP ${response.status}`;
    try {
      const error = await response.json();
      errorDetail = error.detail || error.message || error.error || JSON.stringify(error);
    } catch (e) {
      // If JSON parsing fails, try to get text
      try {
        const text = await response.text();
        errorDetail = text || `HTTP ${response.status}: ${response.statusText}`;
      } catch (textError) {
        errorDetail = `HTTP ${response.status}: ${response.statusText || 'Unknown error'}`;
      }
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

export const api = {
  // Health check
  health: () => fetchApi<{ status: string }>('/health'),

  // Policies
  listPolicies: () => fetchApi<{ policies: PolicyRule[] }>('/policies'),
  getPolicy: (id: string) => fetchApi<PolicyRule>(`/policies/${id}`),

  // Analysis
  analyze: (code: string, language: string = 'python', policies?: string[]) =>
    fetchApi<AnalysisResult>('/analyze', {
      method: 'POST',
      body: JSON.stringify({ code, language, policies }),
    }),

  analyzeSummary: (code: string, language: string = 'python') =>
    fetchApi<ViolationSummary>('/analyze/summary', {
      method: 'POST',
      body: JSON.stringify({ code, language }),
    }),

  // Adjudication
  adjudicate: (analysis: AnalysisResult) =>
    fetchApi<AdjudicationResult>('/adjudicate', {
      method: 'POST',
      body: JSON.stringify(analysis),
    }),

  getGuidance: (analysis: AnalysisResult) =>
    fetchApi<{ guidance: string; violation_count: number }>('/adjudicate/guidance', {
      method: 'POST',
      body: JSON.stringify(analysis),
    }),

  // Fix
  fixCode: (code: string, violations: Violation[], language: string = 'python') =>
    fetchApi<{ original_code: string; fixed_code: string; explanation?: string }>('/fix', {
      method: 'POST',
      body: JSON.stringify({ code, violations, language }),
    }),

  // Enforce (full loop)
  enforce: (code: string, language: string = 'python', maxIterations: number = 3) =>
    fetchApi<EnforceResponse>('/enforce', {
      method: 'POST',
      body: JSON.stringify({ 
        code, 
        language, 
        max_iterations: maxIterations 
      }),
    }),

  // Generate
  generate: (spec: string, language: string = 'python', policies?: string[]) =>
    fetchApi<{ code: string; analysis?: string[] }>('/generate', {
      method: 'POST',
      body: JSON.stringify({ spec, language, policies }),
    }),

  // Proof Export
  exportProof: (proofBundle: ProofBundle, format: string = 'json') =>
    fetchApi<{ format: string; content: string }>('/proof/export', {
      method: 'POST',
      body: JSON.stringify({ proof_bundle: proofBundle, format }),
    }),
};

