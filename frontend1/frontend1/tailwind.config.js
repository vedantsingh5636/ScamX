/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        forest: {
          950: '#02160d',
          900: '#052418',
          850: '#083020',
          800: '#0b3d2b',
          700: '#10523a',
          600: '#176c4e',
        },
        mint: {
          25: '#fafdfb',
          50: '#f2f9f5',
          100: '#e4f4ea',
          200: '#cdebd8',
          300: '#a6ddbc',
          400: '#71c699',
          500: '#34b277',
          600: '#109b5e',
        },
        brand: {
          green: '#00BA6A',
          emerald: '#10B981',
          dark: '#052418',
          mint: '#EBF6EF',
          gold: '#F59E0B',
          amber: '#D97706',
          rupee: '#EAB308',
        }
      },
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'Inter', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      animation: {
        'float-slow': 'float 6s ease-in-out infinite',
        'float-delayed': 'float 6s ease-in-out 3s infinite',
        'pulse-subtle': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'dash': 'dash 20s linear infinite',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-10px)' },
        },
        dash: {
          to: { 'stroke-dashoffset': '-100' },
        }
      },
      boxShadow: {
        'glow-green': '0 0 25px -5px rgba(16, 185, 129, 0.3)',
        'glow-emerald': '0 0 40px -10px rgba(0, 186, 106, 0.4)',
        'shield-3d': '0 20px 40px -15px rgba(5, 36, 24, 0.3), inset 0 2px 4px rgba(255, 255, 255, 0.2)',
        'card-soft': '0 10px 30px -5px rgba(5, 36, 24, 0.05), 0 2px 6px -1px rgba(5, 36, 24, 0.02)',
      }
    },
  },
  plugins: [],
}
