export { authenticationTemplate } from './AuthenticationTemplate';
export { databaseTemplate } from './DatabaseTemplate';
export { securityTemplate } from './SecurityTemplate';

export const knowledgeTemplates = {
  authentication: () => import('./AuthenticationTemplate').then(m => m.authenticationTemplate),
  database: () => import('./DatabaseTemplate').then(m => m.databaseTemplate),
  security: () => import('./SecurityTemplate').then(m => m.securityTemplate),
};

export type TemplateCategory = keyof typeof knowledgeTemplates;

export interface KnowledgeTemplate {
  name: string;
  category: string;
  overview: string;
  [key: string]: any;
}

export async function getTemplate(category: TemplateCategory): Promise<KnowledgeTemplate> {
  const loader = knowledgeTemplates[category];
  if (!loader) {
    throw new Error(`Template not found for category: ${category}`);
  }
  return await loader();
}

export function getAvailableTemplates(): TemplateCategory[] {
  return Object.keys(knowledgeTemplates) as TemplateCategory[];
}