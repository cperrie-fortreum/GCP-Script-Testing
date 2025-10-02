#!/usr/bin/env node
/**
 * GCP Comprehensive Audit Script
 * Pulls IAM users/groups, VPC DNS configuration, and storage bucket encryption
 * 
 * Requirements:
 *   npm install @google-cloud/resource-manager @google-cloud/storage @google-cloud/compute
 */

const { ProjectsClient } = require('@google-cloud/resource-manager').v3;
const { Storage } = require('@google-cloud/storage');
const { NetworksClient, SubnetworksClient } = require('@google-cloud/compute').v1;

/**
 * Get IAM users and groups
 */
async function getIAMUsersAndGroups(projectId) {
  console.log('\n' + '='.repeat(70));
  console.log('FETCHING IAM USERS AND GROUPS');
  console.log('='.repeat(70));

  try {
    const client = new ProjectsClient();
    const resource = `projects/${projectId}`;
    const [policy] = await client.getIamPolicy({ resource });

    const users = [];
    const groups = [];
    const serviceAccounts = [];
    const allBindings = [];

    if (policy.bindings) {
      policy.bindings.forEach((binding) => {
        if (binding.members) {
          binding.members.forEach((member) => {
            const bindingInfo = {
              member: member,
              role: binding.role
            };
            
            allBindings.push(bindingInfo);

            if (member.startsWith('user:')) {
              users.push({
                email: member.replace('user:', ''),
                role: binding.role,
                type: 'user'
              });
            } else if (member.startsWith('group:')) {
              groups.push({
                email: member.replace('group:', ''),
                role: binding.role,
                type: 'group'
              });
            } else if (member.startsWith('serviceAccount:')) {
              serviceAccounts.push({
                email: member.replace('serviceAccount:', ''),
                role: binding.role,
                type: 'serviceAccount'
              });
            }
          });
        }
      });
    }

    // Get unique users and groups
    const uniqueUsers = [...new Map(users.map(u => [u.email, u])).values()];
    const uniqueGroups = [...new Map(groups.map(g => [g.email, g])).values()];
    const uniqueServiceAccounts = [...new Map(serviceAccounts.map(s => [s.email, s])).values()];

    console.log(`\nFound ${uniqueUsers.length} unique user accounts`);
    console.log(`Found ${uniqueGroups.length} unique groups`);
    console.log(`Found ${uniqueServiceAccounts.length} unique service accounts`);
    console.log(`Total IAM bindings: ${allBindings.length}\n`);

    // Display sample
    if (uniqueUsers.length > 0) {
      console.log('Sample Users (first 5):');
      uniqueUsers.slice(0, 5).forEach((user, idx) => {
        console.log(`  ${idx + 1}. ${user.email}`);
      });
      if (uniqueUsers.length > 5) console.log(`  ... and ${uniqueUsers.length - 5} more`);
      console.log();
    }

    if (uniqueGroups.length > 0) {
      console.log('Groups:');
      uniqueGroups.forEach((group, idx) => {
        console.log(`  ${idx + 1}. ${group.email}`);
      });
      console.log();
    }

    return {
      users: uniqueUsers,
      groups: uniqueGroups,
      serviceAccounts: uniqueServiceAccounts,
      allBindings: allBindings,
      summary: {
        totalUsers: uniqueUsers.length,
        totalGroups: uniqueGroups.length,
        totalServiceAccounts: uniqueServiceAccounts.length,
        totalBindings: allBindings.length
      }
    };

  } catch (error) {
    console.error('Error fetching IAM policy:', error.message);
    throw error;
  }
}

/**
 * Get VPC networks with DNS configuration
 */
async function getVPCNetworks(projectId) {
  console.log('\n' + '='.repeat(70));
  console.log('FETCHING VPC NETWORKS AND DNS CONFIGURATION');
  console.log('='.repeat(70));

  try {
    const networksClient = new NetworksClient();
    const subnetworksClient = new SubnetworksClient();

    // Get all networks
    const [networks] = await networksClient.list({
      project: projectId
    });

    console.log(`\nFound ${networks.length} VPC networks\n`);

    const networksData = [];

    for (const network of networks) {
      // Get subnets for this network
      const networkName = network.name;
      const subnets = [];

      // List all regions to get subnets
      try {
        const allSubnets = await subnetworksClient.aggregatedListAsync({
          project: projectId
        });

        for await (const [region, subnetsResponse] of allSubnets) {
          if (subnetsResponse.subnetworks) {
            for (const subnet of subnetsResponse.subnetworks) {
              if (subnet.network && subnet.network.includes(networkName)) {
                subnets.push({
                  name: subnet.name,
                  region: region.replace('regions/', ''),
                  ipCidrRange: subnet.ipCidrRange,
                  privateIpGoogleAccess: subnet.privateIpGoogleAccess || false,
                  gatewayAddress: subnet.gatewayAddress
                });
              }
            }
          }
        }
      } catch (subnetError) {
        console.log(`  Warning: Could not fetch subnets for ${networkName}`);
      }

      const networkInfo = {
        name: network.name,
        id: network.id,
        description: network.description || 'No description',
        autoCreateSubnetworks: network.autoCreateSubnetworks || false,
        routingMode: network.routingConfig?.routingMode || 'REGIONAL',
        mtu: network.mtu || 1460,
        subnets: subnets,
        // DNS configuration
        dns: {
          enableInboundForwarding: network.enableInboundForwarding || false,
          dnsServerPolicy: network.dnsPolicy || 'default',
          internalIpv6Range: network.internalIpv6Range || null
        },
        peerings: network.peerings || [],
        creationTimestamp: network.creationTimestamp
      };

      networksData.push(networkInfo);

      // Display network info
      console.log(`Network: ${network.name}`);
      console.log(`  Auto-create subnets: ${networkInfo.autoCreateSubnetworks}`);
      console.log(`  Routing mode: ${networkInfo.routingMode}`);
      console.log(`  MTU: ${networkInfo.mtu}`);
      console.log(`  DNS Policy: ${networkInfo.dns.dnsServerPolicy}`);
      console.log(`  Inbound DNS Forwarding: ${networkInfo.dns.enableInboundForwarding}`);
      console.log(`  Subnets: ${subnets.length}`);
      
      if (subnets.length > 0) {
        subnets.forEach(subnet => {
          console.log(`    - ${subnet.name} (${subnet.region}): ${subnet.ipCidrRange}`);
        });
      }
      
      if (networkInfo.peerings.length > 0) {
        console.log(`  VPC Peerings: ${networkInfo.peerings.length}`);
        networkInfo.peerings.forEach(peer => {
          console.log(`    - ${peer.name}: ${peer.network}`);
        });
      }
      console.log();
    }

    return {
      networks: networksData,
      summary: {
        totalNetworks: networksData.length,
        totalSubnets: networksData.reduce((sum, net) => sum + net.subnets.length, 0),
        networksWithDnsForwarding: networksData.filter(n => n.dns.enableInboundForwarding).length
      }
    };

  } catch (error) {
    console.error('Error fetching VPC networks:', error.message);
    throw error;
  }
}

/**
 * Get storage buckets with encryption details
 */
async function getStorageBuckets(projectId) {
  console.log('\n' + '='.repeat(70));
  console.log('FETCHING STORAGE BUCKETS AND ENCRYPTION');
  console.log('='.repeat(70));

  try {
    const storage = new Storage({ projectId });
    const [buckets] = await storage.getBuckets();

    console.log(`\nFound ${buckets.length} storage buckets\n`);

    const bucketsData = [];

    for (const bucket of buckets) {
      const [metadata] = await bucket.getMetadata();

      // Determine encryption type
      let encryptionType = 'Google-managed (default)';
      let encryptionKeyName = null;

      if (metadata.encryption && metadata.encryption.defaultKmsKeyName) {
        encryptionType = 'Customer-managed (CMEK)';
        encryptionKeyName = metadata.encryption.defaultKmsKeyName;
      }

      const bucketInfo = {
        name: bucket.name,
        location: metadata.location,
        locationType: metadata.locationType,
        storageClass: metadata.storageClass,
        created: metadata.timeCreated,
        encryption: {
          type: encryptionType,
          kmsKeyName: encryptionKeyName,
          defaultEventBasedHold: metadata.defaultEventBasedHold || false
        },
        versioning: {
          enabled: metadata.versioning?.enabled || false
        },
        lifecycle: {
          hasRules: (metadata.lifecycle?.rule && metadata.lifecycle.rule.length > 0) || false,
          rulesCount: metadata.lifecycle?.rule?.length || 0
        },
        iamConfiguration: {
          uniformBucketLevelAccess: {
            enabled: metadata.iamConfiguration?.uniformBucketLevelAccess?.enabled || false,
            lockedTime: metadata.iamConfiguration?.uniformBucketLevelAccess?.lockedTime || null
          },
          publicAccessPrevention: metadata.iamConfiguration?.publicAccessPrevention || 'inherited'
        },
        labels: metadata.labels || {},
        retentionPolicy: metadata.retentionPolicy || null,
        cors: metadata.cors || [],
        website: metadata.website || null,
        logging: metadata.logging || null
      };

      bucketsData.push(bucketInfo);

      // Display bucket info
      console.log(`Bucket: ${bucket.name}`);
      console.log(`  Location: ${metadata.location} (${metadata.locationType})`);
      console.log(`  Storage Class: ${metadata.storageClass}`);
      console.log(`  Encryption: ${encryptionType}`);
      if (encryptionKeyName) {
        console.log(`  KMS Key: ${encryptionKeyName}`);
      }
      console.log(`  Versioning: ${bucketInfo.versioning.enabled ? 'Enabled' : 'Disabled'}`);
      console.log(`  Uniform Bucket-Level Access: ${bucketInfo.iamConfiguration.uniformBucketLevelAccess.enabled ? 'Enabled' : 'Disabled'}`);
      console.log(`  Public Access Prevention: ${bucketInfo.iamConfiguration.publicAccessPrevention}`);
      console.log(`  Lifecycle Rules: ${bucketInfo.lifecycle.rulesCount}`);
      console.log();
    }

    // Calculate summary statistics
    const googleManaged = bucketsData.filter(b => b.encryption.type === 'Google-managed (default)').length;
    const customerManaged = bucketsData.filter(b => b.encryption.type === 'Customer-managed (CMEK)').length;
    const versioningEnabled = bucketsData.filter(b => b.versioning.enabled).length;
    const uniformAccessEnabled = bucketsData.filter(b => b.iamConfiguration.uniformBucketLevelAccess.enabled).length;
    const publicAccessEnforced = bucketsData.filter(b => b.iamConfiguration.publicAccessPrevention === 'enforced').length;

    console.log('Storage Summary:');
    console.log(`  Google-managed encryption: ${googleManaged}`);
    console.log(`  Customer-managed encryption (CMEK): ${customerManaged}`);
    console.log(`  Versioning enabled: ${versioningEnabled}`);
    console.log(`  Uniform bucket-level access: ${uniformAccessEnabled}`);
    console.log(`  Public access prevention enforced: ${publicAccessEnforced}`);

    return {
      buckets: bucketsData,
      summary: {
        totalBuckets: bucketsData.length,
        googleManagedEncryption: googleManaged,
        customerManagedEncryption: customerManaged,
        versioningEnabled: versioningEnabled,
        uniformBucketLevelAccess: uniformAccessEnabled,
        publicAccessPrevention: publicAccessEnforced
      }
    };

  } catch (error) {
    console.error('Error fetching storage buckets:', error.message);
    throw error;
  }
}

/**
 * Save report to file
 */
async function saveToFile(data, filename) {
  const fs = require('fs').promises;
  try {
    await fs.writeFile(filename, JSON.stringify(data, null, 2));
    console.log(`\nFull report saved to: ${filename}`);
  } catch (error) {
    console.error('Error saving file:', error.message);
  }
}

/**
 * Main function
 */
async function main() {
  const args = process.argv.slice(2);
  const projectId = args[0] || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCP_PROJECT;

  if (!projectId) {
    console.error('Error: Project ID is required');
    console.error('\nUsage:');
    console.error('  node gcp_audit.js PROJECT_ID');
    console.error('  node gcp_audit.js PROJECT_ID output.json');
    console.error('\nOr set GOOGLE_CLOUD_PROJECT environment variable');
    process.exit(1);
  }

  const outputFile = args[1] || 'gcp_comprehensive_audit.json';

  console.log('\n' + '='.repeat(70));
  console.log('GCP COMPREHENSIVE AUDIT');
  console.log('='.repeat(70));
  console.log(`Project ID: ${projectId}`);
  console.log(`Timestamp: ${new Date().toISOString()}`);

  const auditReport = {
    projectId: projectId,
    timestamp: new Date().toISOString(),
    iam: null,
    vpcs: null,
    storage: null
  };

  try {
    // Collect IAM data
    console.log('\n[1/3] Collecting IAM Users and Groups...');
    auditReport.iam = await getIAMUsersAndGroups(projectId);

    // Collect VPC data
    console.log('\n[2/3] Collecting VPC Networks and DNS Configuration...');
    auditReport.vpcs = await getVPCNetworks(projectId);

    // Collect Storage data
    console.log('\n[3/3] Collecting Storage Buckets and Encryption...');
    auditReport.storage = await getStorageBuckets(projectId);

    // Save to file
    await saveToFile(auditReport, outputFile);

    // Final summary
    console.log('\n' + '='.repeat(70));
    console.log('AUDIT COMPLETED SUCCESSFULLY');
    console.log('='.repeat(70));
    console.log('\nFinal Summary:');
    console.log(`  IAM Users: ${auditReport.iam.summary.totalUsers}`);
    console.log(`  IAM Groups: ${auditReport.iam.summary.totalGroups}`);
    console.log(`  Service Accounts: ${auditReport.iam.summary.totalServiceAccounts}`);
    console.log(`  VPC Networks: ${auditReport.vpcs.summary.totalNetworks}`);
    console.log(`  Subnets: ${auditReport.vpcs.summary.totalSubnets}`);
    console.log(`  Networks with DNS Forwarding: ${auditReport.vpcs.summary.networksWithDnsForwarding}`);
    console.log(`  Storage Buckets: ${auditReport.storage.summary.totalBuckets}`);
    console.log(`  Buckets with CMEK: ${auditReport.storage.summary.customerManagedEncryption}`);
    console.log(`  Buckets with Versioning: ${auditReport.storage.summary.versioningEnabled}`);
    console.log('\n' + '='.repeat(70));

  } catch (error) {
    console.error('\n\nAudit failed:', error.message);
    console.error('\nMake sure you have the following permissions:');
    console.error('  - resourcemanager.projects.getIamPolicy');
    console.error('  - compute.networks.list');
    console.error('  - compute.subnetworks.list');
    console.error('  - storage.buckets.list');
    console.error('  - storage.buckets.getIamPolicy');
    process.exit(1);
  }
}

// Run the script
if (require.main === module) {
  main();
}

module.exports = { getIAMUsersAndGroups, getVPCNetworks, getStorageBuckets };