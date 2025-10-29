# NACF Disaster Recovery Runbook

This document outlines the procedures for recovering the NACF system in the event of a disaster.

## Recovery Time Objective (RTO) and Recovery Point Objective (RPO)

- **RTO (Recovery Time Objective)**: 2 hours
- **RPO (Recovery Point Objective)**: 15 minutes

## Prerequisites

1. Access to the Kubernetes cluster with admin privileges
2. Velero CLI installed and configured
3. Access to the backup storage location
4. Sufficient resources in the recovery environment

## Recovery Procedures

### 1. Initial Assessment

1. **Identify the scope of the disaster**:
   - Single pod failure
   - Node failure
   - Namespace/application failure
   - Complete cluster failure
   - Data center/region failure

2. **Check backup status**:
   ```bash
   velero backup get
   velero backup describe <backup-name>
   ```

### 2. Recover the Entire NACF System

```bash
# List available backups
velero backup get

# Restore the latest backup
velero restore create --from-backup <latest-backup-name> --wait

# Monitor restore progress
velero restore describe <restore-name>
velero restore logs <restore-name>
```

### 3. Recover Specific Components

#### Redis
```bash
# Restore Redis from backup
velero restore create --from-backup <backup-name> \
    --include-resources statefulsets,persistentvolumeclaims,persistentvolumes \
    --include-namespaces nacf \
    --selector app.kubernetes.io/component=redis \
    --wait
```

#### Authentication Service
```bash
# Restore Authentication Service
velero restore create --from-backup <backup-name> \
    --include-resources deployments,services,configmaps,secrets \
    --include-namespaces nacf \
    --selector app.kubernetes.io/component=auth-service \
    --wait
```

### 4. Post-Recovery Verification

1. **Verify Pods**:
   ```bash
   kubectl get pods -n nacf
   ```

2. **Check Logs**:
   ```bash
   kubectl logs -n nacf -l app.kubernetes.io/component=auth-service
   ```

3. **Run Health Checks**:
   ```bash
   # Example health check
   curl -X GET https://api.nacf.example.com/healthz
   ```

4. **Validate Data**:
   - Verify database records
   - Check cache consistency
   - Validate file storage contents

### 5. Failback Procedures (If Applicable)

1. **Prepare the primary environment**
2. **Synchronize data**
3. **Update DNS/load balancers**
4. **Verify functionality**
5. **Decommission DR resources**

## Common Recovery Scenarios

### Scenario 1: Accidental Deletion of Namespace

```bash
# 1. Identify the last good backup
velero backup get

# 2. Restore the namespace
velero restore create --from-backup <backup-name> \
    --include-namespaces nacf \
    --wait
```

### Scenario 2: Corrupted Database

```bash
# 1. Scale down the application
kubectl scale deployment -n nacf auth-service --replicas=0

# 2. Restore the database from backup
velero restore create --from-backup <backup-name> \
    --include-resources statefulsets,persistentvolumeclaims,persistentvolumes \
    --include-namespaces nacf \
    --selector app.kubernetes.io/component=redis \
    --wait

# 3. Scale the application back up
kubectl scale deployment -n nacf auth-service --replicas=3
```

## Testing the Disaster Recovery Plan

1. **Scheduled Tests**:
   - Monthly for critical systems
   - Quarterly for all systems

2. **Test Procedures**:
   - Restore to a non-production environment
   - Verify application functionality
   - Validate data consistency
   - Document results and update procedures as needed

## Contact Information

- **Primary On-Call**: [Name] - [Phone] - [Email]
- **Secondary On-Call**: [Name] - [Phone] - [Email]
- **Escalation Path**: [Manager Name] - [Phone] - [Email]

## Appendix: Useful Commands

```bash
# Check Velero server status
velero version

# Get backup details
velero backup describe <backup-name> --details

# Check restore status
velero restore describe <restore-name>

# Get logs for troubleshooting
velero restore logs <restore-name>

# Delete a failed restore
velero restore delete <restore-name>
```

## Revision History

| Date       | Version | Description                | Author         |
|------------|---------|----------------------------|----------------|
| 2025-03-15 | 1.0     | Initial Version            | [Your Name]    |
| 2025-04-01 | 1.1     | Added common scenarios     | [Your Name]    |
