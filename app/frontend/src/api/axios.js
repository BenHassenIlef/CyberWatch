import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:8000",
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("cyberwatch_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("cyberwatch_token");
      localStorage.removeItem("cyberwatch_user");
      const role = localStorage.getItem("cyberwatch_role");
      window.location.href = role === "consultant" ? "/consultant/signin" : "/admin/signin";
    }
    return Promise.reject(error);
  }
);

export default api;
