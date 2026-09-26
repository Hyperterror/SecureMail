/**
 * API client for SecureMailScope backend.
 */

import type { AnalysisResult, UploadResponse, AnalysisProgress } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

/**
 * Upload a PCAP file to the backend.
 */
export async function uploadPcap(file: File): Promise<UploadResponse> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE}/api/upload`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: "Upload failed" }));
    throw new Error(error.detail || `Upload failed: ${res.status}`);
  }

  return res.json();
}

/**
 * Start analysis and stream progress via SSE.
 */
export function analyzeStream(
  analysisId: string,
  onProgress: (progress: AnalysisProgress) => void,
  onComplete: (result: AnalysisResult) => void,
  onError: (error: string) => void,
): () => void {
  const eventSource = new EventSource(`${API_BASE}/api/analyze/${analysisId}`);

  eventSource.onmessage = (event) => {
    try {
      const data: AnalysisProgress = JSON.parse(event.data);

      if (data.stage === "complete" && data.result) {
        onComplete(data.result);
        eventSource.close();
      } else if (data.stage === "error") {
        onError(data.message);
        eventSource.close();
      } else {
        onProgress(data);
      }
    } catch (e) {
      console.error("Failed to parse SSE event:", e);
    }
  };

  eventSource.onerror = () => {
    onError("Connection to analysis stream lost");
    eventSource.close();
  };

  return () => eventSource.close();
}

/**
 * Generate demo analysis data (no PCAP needed).
 */
export async function generateDemo(): Promise<AnalysisResult> {
  const res = await fetch(`${API_BASE}/api/demo`, { method: "POST" });
  if (!res.ok) {
    throw new Error(`Demo generation failed: ${res.status}`);
  }
  return res.json();
}

/**
 * Get a completed analysis result.
 */
export async function getAnalysis(analysisId: string): Promise<AnalysisResult> {
  const res = await fetch(`${API_BASE}/api/analysis/${analysisId}`);
  if (!res.ok) {
    throw new Error(`Analysis not found: ${res.status}`);
  }
  return res.json();
}

/**
 * Get export URLs.
 */
export function getExportUrl(analysisId: string, format: "json" | "html"): string {
  return `${API_BASE}/api/analysis/${analysisId}/export/${format}`;
}
