// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import react from '@astrojs/react';
import { sidebar } from './src/sidebar.generated'


// https://astro.build/config
export default defineConfig({
	integrations: [
    react(),
		starlight({
			title: 'My Docs',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/withastro/starlight' }],
			sidebar: sidebar,
		}),
	],
});