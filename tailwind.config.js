/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/**/*.html', // scan semua file html di folder templates
    './static/**/*.js',      // jika ada file JS yang pakai tailwind
  ],
    theme: {
    extend: {
      spacing: {
        '18': '4.5rem', // 72px
        '65': '16.25rem', // 260px
      },
      boxShadow: {
        'top': '0px -2px 10px rgba(0, 0, 0, 0.1)',
      },
      lineHeight: {
        '19': '4.75rem',
      }
    }
  },
  plugins: [],
}