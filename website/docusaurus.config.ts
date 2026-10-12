import type * as Preset from '@docusaurus/preset-classic';
import type {Config} from '@docusaurus/types';
import {themes as prismThemes} from 'prism-react-renderer';

/** Shown in the navbar and on the install card. Bump on release. */
const latestVersion = '2026.9.21';

const config: Config = {
  title: 'OWASP DockSec',
  tagline: 'Which container findings actually matter, and what to do about them',
  favicon: 'img/docksec-mark.png',

  // The site is served from GitHub Pages. owasp.org/DockSec/ can later be
  // pointed here as a redirect, the way owasp.org/cve-lite-cli/ is - that
  // needs no rebuild, because the canonical URL does not change.
  url: 'https://docksec.owasp.org',
  baseUrl: '/',
  organizationName: 'OWASP',
  projectName: 'DockSec',
  trailingSlash: false,

  // A broken link is a broken promise on a security tool's own site.
  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },
  themes: ['@docusaurus/theme-mermaid'],

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/OWASP/DockSec/tree/main/website/',
          showLastUpdateTime: true,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
        sitemap: {
          changefreq: 'weekly',
          priority: 0.5,
        },
      } satisfies Preset.Options,
    ],
  ],

  plugins: [
    [
      // Local index rather than a hosted search service. DockSec's pitch is
      // that it sends nothing anywhere; its own site should not either.
      '@easyops-cn/docusaurus-search-local',
      {
        hashed: true,
        indexDocs: true,
        indexBlog: false,
        indexPages: true,
        docsRouteBasePath: 'docs',
        searchBarShortcut: true,
        searchBarShortcutKeymap: 'mod+k',
        searchBarPosition: 'right',
      },
    ],
  ],

  themeConfig: {
    image: 'img/docksec-logo.png',
    colorMode: {
      defaultMode: 'dark',
      // Deliberately left switchable: forcing a theme is a needless
      // accessibility cost, and some readers need the light one.
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
    metadata: [
      {
        name: 'description',
        content:
          'OWASP DockSec ranks Docker and Compose findings by real exploitation likelihood (EPSS), ' +
          'detects cross-service exploit chains, and emits copy-and-run fixes. Runs entirely on ' +
          'your own infrastructure, with no API key required.',
      },
      {
        name: 'keywords',
        content:
          'Docker security scanner, container vulnerability scanner, Dockerfile linter, ' +
          'docker compose security, EPSS prioritization, exploit chain detection, SARIF, ' +
          'CycloneDX SBOM, Trivy, Hadolint, OWASP',
      },
    ],
    navbar: {
      // The wordmark already reads "DockSec", so no title text beside it.
      logo: {
        alt: 'OWASP DockSec',
        src: 'img/docksec-logo.png',
        srcDark: 'img/docksec-logo.png',
        width: 132,
      },
      items: [
        {to: '/docs/getting-started', label: 'Get started', position: 'left'},
        {to: '/docs/why-docksec', label: 'Why DockSec', position: 'left'},
        {to: '/docs/cli-reference', label: 'CLI', position: 'left'},
        {to: '/docs/comparison', label: 'Compare', position: 'left'},
        {to: '/docs/case-studies', label: 'Case studies', position: 'left'},
        {to: '/docs/press', label: 'Press', position: 'left'},
        {to: '/docs/about', label: 'About', position: 'left'},
        {
          href: 'https://owasp.org/www-project-docksec/',
          label: 'OWASP Project',
          position: 'right',
        },
        {
          href: 'https://pypi.org/project/docksec/',
          label: `PyPI ${latestVersion}`,
          position: 'right',
        },
        {
          href: 'https://github.com/OWASP/DockSec',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Get started', to: '/docs/getting-started'},
            {label: 'CLI reference', to: '/docs/cli-reference'},
            {label: 'CI integration', to: '/docs/ci'},
            {label: 'Evaluation guide', to: '/docs/evaluation-guide'},
          ],
        },
        {
          title: 'Understand',
          items: [
            {label: 'Why DockSec', to: '/docs/why-docksec'},
            {label: 'Exploit chains', to: '/docs/exploit-chains'},
            {label: 'Case studies', to: '/docs/case-studies'},
            {label: 'What it does not do', to: '/docs/limitations'},
            {label: 'Compare with other tools', to: '/docs/comparison'},
            {label: 'Press and talks', to: '/docs/press'},
          ],
        },
        {
          title: 'Project',
          items: [
            {label: 'GitHub', href: 'https://github.com/OWASP/DockSec'},
            {label: 'PyPI', href: 'https://pypi.org/project/docksec/'},
            {
              label: 'OWASP project page',
              href: 'https://owasp.org/www-project-docksec/',
            },
            {
              label: 'Report an issue',
              href: 'https://github.com/OWASP/DockSec/issues',
            },
            {label: 'About the project', to: '/docs/about'},
          ],
        },
      ],
      copyright:
        `Created by <a href="https://github.com/advaitpatel">Advait Patel</a>, ` +
        `with co-lead <a href="https://github.com/arkid15r">Arkadii Yakovets</a> ` +
        `and the OWASP community.<br />` +
        `Copyright © ${new Date().getFullYear()} The OWASP Foundation. ` +
        `DockSec is released under the MIT License.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'docker', 'yaml', 'json', 'python'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
