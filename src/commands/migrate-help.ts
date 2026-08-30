/** Engine-free help dispatch for the two `gbrain migrate` command forms. */

export function printMigrateHelp(): void {
  console.log('Usage: gbrain migrate --to <supabase|pglite> [--url <url>] [--path <path>] [--force]');
  console.log('       gbrain migrate embeddings --to <provider:model> [--dim N] [--dry-run] [--yes]');
  console.log('');
  console.log('The first form transfers the brain between engines; the second re-embeds');
  console.log('onto a different embedding provider (run `gbrain migrate embeddings --help`).');
}

export async function runMigrateHelp(_engine: never, args: string[]): Promise<void> {
  if (args[0] === 'embeddings') {
    const { printMigrateEmbeddingsHelp } = await import('./migrate-embeddings.ts');
    printMigrateEmbeddingsHelp();
    return;
  }
  printMigrateHelp();
}
