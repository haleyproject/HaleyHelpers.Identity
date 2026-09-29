<script lang="ts">
  import type { Section } from '../lib/types';
  import haleyLogo from '../assets/haley.svg';
  export let logo = haleyLogo;
  export let brand = 'Haley';
  export let subtitle = 'Identity';
  export let active: Section;
  export let capabilities: string[];
  export let collapsed: boolean;
  export let onToggle: () => void;
  export let onSelect: (section: Section) => void;
  export let onLogout: () => void;

  export let items: { id: Section; label: string; icon: string; capability?: string }[] = [
    { id: 'users', label: 'Identity', icon: '◎' },
    { id: 'federation', label: 'Federation', icon: '↗' }
  ];
</script>

<aside class="sidebar" class:collapsed>
  <div class="sidebar-brand">
    <div class="brand-mark small"><img src={logo} alt="" /></div>
    <div class="sidebar-brand-copy"><strong>{brand}</strong><small>{subtitle}</small></div>
    <button
      class="sidebar-toggle"
      type="button"
      aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
      aria-expanded={!collapsed}
      title={collapsed ? 'Expand navigation' : 'Collapse navigation'}
      onclick={onToggle}>
      <span></span><span></span><span></span>
    </button>
  </div>

  <nav aria-label="Admin sections">
    {#each items.filter(item => !item.capability || capabilities.includes(item.capability)) as item}
      <button class:active={active === item.id} title={collapsed ? item.label : undefined} onclick={() => onSelect(item.id)}>
        <span class="nav-icon">{item.icon}</span>
        <span class="nav-copy"><strong>{item.label}</strong></span>
      </button>
    {/each}
  </nav>

  <div class="sidebar-foot">
    <div class="local-badge" title={collapsed ? 'Admin session: boundary protected' : undefined}><span></span><div class="sidebar-foot-copy"><strong>Admin session</strong><small>Boundary protected</small></div></div>
    <button class="quiet full sidebar-lock" title={collapsed ? 'Lock console' : undefined} aria-label="Lock console" onclick={onLogout}><span aria-hidden="true">⏻</span><strong>Lock console</strong></button>
  </div>
</aside>
