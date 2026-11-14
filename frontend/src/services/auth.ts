import { api } from "./api";

export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  user_type: "CUSTOMER" | "STAFF" | "SYSTEM";
  roles: string[];
  permissions: string[];
  mfa_enabled: boolean;
}

export interface Me {
  user: User;
  aal: number;
  amr: string[];
  device_trusted: boolean;
  session_expires_at: string;
}

export type LoginStatus = "authenticated" | "mfa_required" | "mfa_enrollment_required";
export interface LoginResult { status: LoginStatus; user: User | null; new_device: boolean }
export interface EnrollStart { secret: string; otpauth_uri: string; qr_code: string }
export interface EnrollConfirm { status: "mfa_enabled" | "authenticated"; recovery_codes: string[]; user: User | null }
export interface SessionInfo {
  id: string; device: string | null; ip: string | null; created_at: string; last_activity: string; current: boolean;
}

export const login = (email: string, password: string) =>
  api.post<LoginResult>("/auth/login", { email, password }).then((r) => r.data);

export interface RegisterInput {
  first_name: string; last_name: string; address: string; city: string; phone: string; email: string;
  profession: string; password: string;
}
export interface RegisterResult extends LoginResult { card_pin: string; iban: string; agency: string; branch_code: string }
export interface City { city: string; agency: string; branch_code: string }

export const fetchCities = () => api.get<City[]>("/auth/register/cities").then((r) => r.data);

export const register = (input: RegisterInput) =>
  api.post<RegisterResult>("/auth/register", input).then((r) => r.data);

export const verifyMfa = (code: string, trustDevice: boolean) =>
  api.post<{ status: "authenticated"; user: User; recovery_codes_left: number | null }>(
    "/auth/mfa/verify", { code, trust_device: trustDevice }).then((r) => r.data);

export const startEnrollment = (currentPassword?: string) =>
  api.post<EnrollStart>("/auth/mfa/enroll/start", { current_password: currentPassword }).then((r) => r.data);

export const confirmEnrollment = (code: string) =>
  api.post<EnrollConfirm>("/auth/mfa/enroll/confirm", { code }).then((r) => r.data);

export const fetchMe = () => api.get<Me>("/auth/me").then((r) => r.data);
export const logout = () => api.post("/auth/logout").then(() => undefined);
export const fetchSessions = () => api.get<SessionInfo[]>("/auth/sessions").then((r) => r.data);
export const revokeSession = (id: string) => api.delete(`/auth/sessions/${id}`).then(() => undefined);
