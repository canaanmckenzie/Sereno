/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // SR-71 Blackbird inspired palette - dark, sleek, minimal
        sereno: {
          bg: "#0a0a0b",
          surface: "#121214",
          border: "#1e1e21",
          hover: "#252529",
          text: "#e4e4e7",
          muted: "#71717a",
          accent: "#3b82f6",
          success: "#22c55e",
          warning: "#eab308",
          danger: "#ef4444",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "SF Mono", "Consolas", "monospace"],
        sans: ["Inter", "SF Pro Display", "system-ui", "sans-serif"],
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "fade-in": "fadeIn 0.2s ease-out",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0", transform: "translateY(-4px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};
