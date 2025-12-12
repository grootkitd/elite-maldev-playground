import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: ["./pages/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./app/**/*.{ts,tsx}", "./src/**/*.{ts,tsx}"],
  prefix: "",
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        display: ['Space Grotesk', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
          glow: "hsl(var(--primary-glow))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        success: "hsl(var(--success))",
        warning: "hsl(var(--warning))",
        info: "hsl(var(--info))",
        cyber: {
          blue: "hsl(var(--cyber-blue))",
          purple: "hsl(var(--cyber-purple))",
          pink: "hsl(var(--cyber-pink))",
          orange: "hsl(var(--cyber-orange))",
        },
        code: {
          bg: "hsl(var(--code-bg))",
        },
        terminal: {
          bg: "hsl(var(--terminal-bg))",
        },
        tip: {
          bg: "hsl(var(--tip-bg))",
          border: "hsl(var(--tip-border))",
          text: "hsl(var(--tip-text))",
        },
        example: {
          bg: "hsl(var(--example-bg))",
          border: "hsl(var(--example-border))",
          text: "hsl(var(--example-text))",
        },
        concept: {
          bg: "hsl(var(--concept-bg))",
          border: "hsl(var(--concept-border))",
          text: "hsl(var(--concept-text))",
        },
      },
      boxShadow: {
        'glow-xs': '0 0 5px hsl(var(--primary) / 0.2)',
        'glow-sm': '0 0 10px hsl(var(--primary) / 0.3)',
        'glow-md': '0 0 25px hsl(var(--primary-glow) / 0.35)',
        'glow-lg': '0 0 40px hsl(var(--primary-glow) / 0.4)',
        'glow-xl': '0 0 60px hsl(var(--primary-glow) / 0.5)',
        'inner-glow': 'inset 0 0 20px hsl(var(--primary) / 0.1)',
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        "pulse-glow": {
          "0%, 100%": { boxShadow: "0 0 20px hsl(var(--primary) / 0.3)" },
          "50%": { boxShadow: "0 0 40px hsl(var(--primary-glow) / 0.5)" },
        },
        "slide-up": {
          "0%": { transform: "translateY(20px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        "slide-in-right": {
          "0%": { transform: "translateX(20px)", opacity: "0" },
          "100%": { transform: "translateX(0)", opacity: "1" },
        },
        "fade-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        "glow-pulse": {
          "0%, 100%": { 
            boxShadow: "0 0 5px hsl(var(--primary) / 0.4), 0 0 10px hsl(var(--primary) / 0.2)",
            borderColor: "hsl(var(--primary) / 0.5)"
          },
          "50%": { 
            boxShadow: "0 0 15px hsl(var(--primary) / 0.6), 0 0 25px hsl(var(--primary) / 0.3)",
            borderColor: "hsl(var(--primary))"
          },
        },
        "float": {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-5px)" },
        },
        "matrix": {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "pulse-glow": "pulse-glow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "slide-up": "slide-up 0.5s ease-out",
        "slide-in-right": "slide-in-right 0.4s ease-out",
        "fade-in": "fade-in 0.4s ease-out",
        "glow-pulse": "glow-pulse 2s ease-in-out infinite",
        "float": "float 3s ease-in-out infinite",
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic': 'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
        'cyber-grid': 'linear-gradient(hsl(var(--primary) / 0.03) 1px, transparent 1px), linear-gradient(90deg, hsl(var(--primary) / 0.03) 1px, transparent 1px)',
      },
      backgroundSize: {
        'grid': '50px 50px',
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
} satisfies Config;
