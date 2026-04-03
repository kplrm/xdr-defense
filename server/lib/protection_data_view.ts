import { getProtectionIndexName, type ProtectionNamespace } from './protection_registry';

export function protectionDataViewId(namespace: ProtectionNamespace): string {
  return `xdr-defense-${namespace}-data-view`;
}

export async function ensureProtectionDataView(repo: any, namespace: ProtectionNamespace): Promise<void> {
  const result = await repo.bulkCreate(
    [
      {
        type: 'index-pattern',
        id: protectionDataViewId(namespace),
        attributes: {
          title: getProtectionIndexName(namespace),
          fields: '[]'
        },
        references: []
      }
    ],
    { overwrite: true }
  );

  const savedObject = result?.saved_objects?.[0];
  if (savedObject?.error) {
    throw new Error(
      `Failed to install ${namespace} data view (${savedObject.error.statusCode}): ${savedObject.error.message}`
    );
  }
}
