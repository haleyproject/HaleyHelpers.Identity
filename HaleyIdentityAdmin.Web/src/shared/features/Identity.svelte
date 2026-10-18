<script lang="ts">
  // Identity = the account directory. Selecting Control on a row opens that account as a full
  // page (left rail of sections) instead of a popup; see Users.svelte.
  import Users from './Users.svelte';
  export let onAccess: (subjectId: string, displayName?: string) => void = () => {};
</script>

<Users {onAccess} />
