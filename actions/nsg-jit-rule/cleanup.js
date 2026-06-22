/**
 * NSG JIT Rule Cleanup Post-Action
 *
 * Automatically reverts (deletes) NSG rules created by the nsg-jit-rule action.
 * This is designed to run as a post-action for automatic cleanup/garbage collection.
 *
 * Enterprise Features:
 * - Graceful handling of missing rules
 * - Cleanup verification
 * - Comprehensive audit logging
 * - Safe error recovery
 *
 * @author BC Government
 * @version 1.0.0
 */

const core = require('@actions/core');
const { execSync } = require('child_process');

const MAX_CLEANUP_RETRIES = 2;

/**
 * Retry wrapper for cleanup operations
 */
async function retryCleanup(fn, context = '') {
  let lastError;
  for (let attempt = 1; attempt <= MAX_CLEANUP_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt < MAX_CLEANUP_RETRIES) {
        const backoffMs = 500 * Math.pow(2, attempt - 1);
        core.warning(`${context} attempt ${attempt} failed, retrying in ${backoffMs}ms: ${error.message}`);
        await new Promise(resolve => setTimeout(resolve, backoffMs));
      }
    }
  }
  throw lastError;
}

/**
 * Delete NSG rule
 */
async function deleteRule(resourceGroup, nsgName, ruleName) {
  try {
    core.debug(`Attempting to delete rule: ${ruleName}`);

    execSync(
      `az network nsg rule delete ` +
      `--resource-group "${resourceGroup}" ` +
      `--nsg-name "${nsgName}" ` +
      `--name "${ruleName}" ` +
      `--no-wait`,
      { encoding: 'utf8' }
    );

    core.info(`✓ Initiated deletion of rule: ${ruleName}`);
  } catch (error) {
    // If rule doesn't exist (404), that's OK - cleanup succeeded
    if (error.message?.includes('NotFound') || error.message?.includes('does not exist')) {
      core.info(`Rule already removed or doesn't exist: ${ruleName}`);
      return;
    }
    throw error;
  }
}

/**
 * Verify rule deletion
 */
async function verifyCleanup(resourceGroup, nsgName, ruleName, maxAttempts = 5) {
  const startTime = Date.now();
  const timeout = 60000; // 60 second timeout

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      // Try to fetch the rule - if it fails with 404, cleanup is complete
      execSync(
        `az network nsg rule show --resource-group "${resourceGroup}" --nsg-name "${nsgName}" --name "${ruleName}" -o json`,
        { encoding: 'utf8', stdio: 'pipe' }
      );

      // Rule still exists, wait and retry
      const elapsed = Date.now() - startTime;
      if (elapsed > timeout) {
        throw new Error(`Cleanup verification timeout after ${elapsed}ms`);
      }

      const waitTime = Math.min(2000 * attempt, 10000);
      core.debug(`Rule still exists (attempt ${attempt}/${maxAttempts}), waiting ${waitTime}ms...`);
      await new Promise(resolve => setTimeout(resolve, waitTime));

    } catch (error) {
      // Rule doesn't exist (404) = success
      if (error.message?.includes('NotFound') || error.message?.includes('does not exist') || error.status === 404) {
        core.info(`✓ Rule deletion verified: ${ruleName}`);
        return true;
      }
      // If it's a different error, throw it
      throw error;
    }
  }

  throw new Error(`Failed to verify rule deletion after ${maxAttempts} attempts`);
}

/**
 * Main cleanup entry point
 */
async function cleanup() {
  const startTime = Date.now();
  const operationId = process.env.NSG_OPERATION_ID || 'unknown';
  const cleanupLog = {
    start_time: new Date().toISOString(),
    action: 'nsg-jit-rule-cleanup',
    operation_id: operationId
  };

  try {
    core.startGroup('🧹 Cleanup: Reverting NSG Rule');

    // Extract cleanup parameters from environment (set by main action via outputs)
    const ruleName = process.env.NSG_RULE_NAME;
    const nsgName = process.env.NSG_NAME;
    const resourceGroup = process.env.RESOURCE_GROUP;
    const subscriptionId = process.env.SUBSCRIPTION_ID;
    const cleanupEnabled = (process.env.NSG_CLEANUP_ENABLED || 'true').toLowerCase() === 'true';

    if (!cleanupEnabled) {
      core.warning('Cleanup explicitly disabled by input. Rule will be retained.');
      await core.summary
        .addHeading('NSG JIT Rule Cleanup Skipped')
        .addTable([
          [{ data: 'Property', header: true }, { data: 'Value', header: true }],
          ['Operation ID', operationId],
          ['Reason', 'cleanup-enabled input set to false']
        ])
        .write();
      core.endGroup();
      return;
    }

    // If no parameters set, this is likely a manual post-action execution without prior main action
    if (!ruleName || !nsgName || !resourceGroup) {
      core.warning('Cleanup parameters not set. Cleanup skipped.');
      core.info('This post-action should only run after nsg-jit-rule main action.');
      core.endGroup();
      return;
    }

    core.info('Cleanup Configuration:');
    core.info(`  Rule Name: ${ruleName}`);
    core.info(`  NSG: ${nsgName}`);
    core.info(`  Resource Group: ${resourceGroup}`);
    core.info(`  Subscription: ${subscriptionId}`);

    // Execute deletion with retry logic
    await retryCleanup(
      () => deleteRule(resourceGroup, nsgName, ruleName),
      'Rule deletion'
    );

    // Verify deletion
    await retryCleanup(
      () => verifyCleanup(resourceGroup, nsgName, ruleName),
      'Cleanup verification'
    );

    core.endGroup();

    core.startGroup('📋 Cleanup Summary');

    const duration = Math.round((Date.now() - startTime) / 1000);
    await core.summary
      .addHeading('NSG JIT Rule Cleanup Complete')
      .addTable([
        [{ data: 'Property', header: true }, { data: 'Value', header: true }],
        ['Operation ID', operationId],
        ['Rule Name', ruleName],
        ['NSG', nsgName],
        ['Resource Group', resourceGroup],
        ['Duration', `${duration}s`],
        ['Status', 'Removed']
      ])
      .write();

    cleanupLog.status = 'success';
    cleanupLog.duration_ms = Date.now() - startTime;
    cleanupLog.rule_removed = ruleName;

    core.endGroup();

  } catch (error) {
    core.error(`❌ Cleanup failed: ${error.message}`);
    cleanupLog.status = 'error';
    cleanupLog.error = error.message;
    cleanupLog.duration_ms = Date.now() - startTime;

    // Don't fail the job on cleanup error - log it but let workflow complete
    core.warning('Cleanup encountered an error but workflow will continue. Please verify manual cleanup if needed.');
    core.warning(`Details: ${error.message}`);
  }

  cleanupLog.end_time = new Date().toISOString();
  core.debug(`Cleanup audit log: ${JSON.stringify(cleanupLog)}`);
}

// Execute cleanup
cleanup().catch(error => {
  // Extra safety net
  core.error(`Cleanup action error: ${error.message}`);
});
