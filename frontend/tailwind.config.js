/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#fef2f2',
          100: '#fee2e2',
          200: '#fecaca',
          300: '#fca5a5',
          400: '#f87171',
          500: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
          800: '#991b1b',
          900: '#7f1d1d',
        },
        dark: {
          50: '#f8fafc',
          100: '#1e1e1e',
          200: '#1a1a1a',
          300: '#151515',
          400: '#121212',
          500: '#0f0f0f',
          600: '#0a0a0a',
          700: '#080808',
          800: '#050505',
          900: '#030303',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgb(239 68 68 / 0.5), 0 0 20px rgb(239 68 68 / 0.2)' },
          '100%': { boxShadow: '0 0 10px rgb(239 68 68 / 0.8), 0 0 40px rgb(239 68 68 / 0.4)' },
        }
      }
    },
  },
  plugins: [],
}
