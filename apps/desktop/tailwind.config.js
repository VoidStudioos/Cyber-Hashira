/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        hashira: {
          900: "#0b0f19",
          850: "#0f172a",
          800: "#1e293b",
          700: "#334155",
          accent: "#00f0ff",
          neonRed: "#ff0055",
          neonGreen: "#00ff9d",
          warning: "#ffb703",
        },
      },
    },
  },
  plugins: [],
};
