# User Count Tracking Strategy

## Overview
The `current_user_count` field in the Organisation model tracks the number of active (non-deleted) users for each organisation. This count is used for enforcing subscription plan limits.

## Approach: Full Recount Method

We use the **full recount approach** for maximum accuracy. Every time a user is created, deleted, or restored, we recalculate the entire count from the database.

### Why Full Recount?
- ✅ **Always accurate** - counts actual users in database
- ✅ **No drift** - can't get out of sync
- ✅ **Simple logic** - no complex increment/decrement tracking
- ⚠️ **Slightly slower** - requires a count query each time

### Previous Approach (Removed)
The old incremental approach (`incrementUserCount()`) was removed because:
- ❌ Could drift out of sync due to race conditions
- ❌ Failed transactions could leave incorrect counts
- ❌ Manual database changes weren't reflected

## Implementation

### User Creation
**File**: `services/user.service.new.js:174-179`
```javascript
// After creating user
const currentCount = await getUserCountByOrganisation(primaryOrganisationId);
await updateOrganisationById(primaryOrganisationId, {
  current_user_count: currentCount,
});
```

### User Deletion (Soft Delete)
**File**: `services/user.service.new.js:512-515`
```javascript
await softDeleteUser(userId, deletedBy, reason);
// Update count after deletion
const currentCount = await getUserCountByOrganisation(user.organisation_id);
await updateOrganisationById(user.organisation_id, {
  current_user_count: currentCount,
});
```

### User Restoration
**File**: `services/user.service.new.js:532-535`
```javascript
await restoreUser(userId, restoredBy);
// Update count after restoration
const currentCount = await getUserCountByOrganisation(user.organisation_id);
await updateOrganisationById(user.organisation_id, {
  current_user_count: currentCount,
});
```

## Count Query Function

**File**: `repositories/userRepository/user.repository.js:352-357`
```javascript
export const getUserCountByOrganisation = async (organisationId) => {
  return await User.countDocuments({
    organisation_id: organisationId,
    is_deleted: false,  // Only counts active users
  });
};
```

## Limit Enforcement

**File**: `repositories/organisationRepository/organisation.repository.js:388-399`
```javascript
export const checkUserLimit = async (id) => {
  const org = await Organisation.findById(id).populate('subscription_plan_id');
  if (!org) return { canAdd: false, error: 'Organisation not found' };

  const isOverLimit = await org.isOverUserLimit();
  return {
    canAdd: !isOverLimit,
    currentCount: org.current_user_count,
    maxAllowed: org.subscription_plan_id.max_users,
    isOverLimit
  };
};
```

**File**: `models/organisation.model.js:307-310`
```javascript
organisationSchema.methods.isOverUserLimit = async function() {
  await this.populate('subscription_plan_id');
  return this.current_user_count >= this.subscription_plan_id.max_users;
};
```

## Maintenance Scripts

### Check User Limits
**File**: `scripts/check-user-limits.js`

Displays current user counts vs limits for all organisations:
```bash
node scripts/check-user-limits.js
```

### Fix User Counts
**File**: `scripts/fix-user-counts.js`

Recalculates and fixes `current_user_count` for all organisations:
```bash
node scripts/fix-user-counts.js
```

Run this script if you suspect counts are incorrect (e.g., after manual database changes).

## Troubleshooting

### Count is incorrect
1. Run `node scripts/check-user-limits.js` to verify the issue
2. Run `node scripts/fix-user-counts.js` to correct all counts
3. Check if user creation/deletion code is properly calling the update logic

### User creation fails with "User limit reached"
1. Verify the actual user count vs the limit
2. Check if `current_user_count` is accurate
3. Check if the subscription plan's `max_users` is correct
4. Run the fix script if counts are out of sync

## Changes Made (2024)

1. **Removed incremental functions**: Deleted `incrementUserCount()` and `incrementAssetCount()` from `organisation.repository.js`
2. **Updated user creation**: Changed from `incrementUserCount()` to full recount in `user.service.new.js`
3. **Fixed isOverUserLimit()**: Changed from `>` to `>=` for proper limit enforcement
4. **Created maintenance scripts**: Added check and fix scripts for debugging
