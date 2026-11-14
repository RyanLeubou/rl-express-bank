import axios from "axios";
import { api } from "./api";
import type { ReadyResponse } from "../types/health";

/** Une réponse 503 reste exploitable : elle décrit quelle dépendance est tombée. */
export async function fetchReadiness(): Promise<ReadyResponse> {
  try {
    const { data } = await api.get<ReadyResponse>("/health/ready");
    return data;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 503 && error.response.data?.checks) {
      return error.response.data as ReadyResponse;
    }
    throw error;
  }
}
