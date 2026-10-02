# QFree Role Separation Implementation

Implemented directly in this build:

- Main QFree app exposes Patient, Provider, Register Facility, and Sign Out only.
- Operations Admin/Admin dashboard is removed from the normal app routing.
- Super Admin is a separate `/super-admin` portal.
- Super Admin portal is strictly restricted to `SUPER_ADMIN`.
- Legacy `ADMIN` role remains in the type/database for migration compatibility but receives no admin-console access.
- Existing platform/admin API capabilities formerly assigned to ADMIN now require SUPER_ADMIN.
- Provider ownership remains enforced for PROVIDER; SUPER_ADMIN has global oversight.
- New registrations can only become PATIENT or PROVIDER; privileged roles cannot be self-assigned.
- Only an existing SUPER_ADMIN can assign the SUPER_ADMIN role.
- Demo role switching has been removed from the normal app header.
- Existing provider image, promotions, feature-control, branding, support, maintenance, and Super Admin modules are preserved.
- The seeded `ops@qfree.health` account is migrated to `SUPER_ADMIN` in the included persistent demo database.

Validation:
- TypeScript/TSX syntax transpilation check: passed for all source files.
- Full Vite build could not be executed because project dependencies are not installed in this environment; package installation timed out.
