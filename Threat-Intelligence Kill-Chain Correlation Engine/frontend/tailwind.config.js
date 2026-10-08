/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Dark security dashboard palette
        'bg-dark':    '#0f1117',
        'bg-card':    '#1a1d27',
        'bg-border':  '#2a2d3e',
        'accent-red': '#ef4444',
        'accent-orange': '#f97316',
        'accent-yellow': '#eab308',
        'accent-green':  '#22c55e',
        'accent-blue':   '#3b82f6',
        'accent-purple': '#a855f7',
      }
    },
  },
  plugins: [],
}
