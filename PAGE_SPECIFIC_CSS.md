# Page-Specific CSS System

## Overview

This task manager now uses a page-specific CSS system to ensure that styling changes on one page won't affect other pages. This provides better isolation, maintainability, and prevents CSS conflicts.

## How It Works

### 1. Base Templates
Both `base.html` and `auth_base.html` have been updated to:
- Load core shared CSS (`style.css`) for all pages
- Conditionally load page-specific CSS based on the current route
- Add page-specific body classes for targeted styling

### 2. Body Classes
Each page now has a unique body class:
- Dashboard: `page-index`
- Projects: `page-all_projects`
- Create Project: `page-create_project`
- Project Detail: `page-project_detail`
- Focus Timer: `page-focus_timer`
- Workspaces: `page-workspaces`
- Create Workspace: `page-create_workspace`
- Workspace Detail: `page-workspace_detail`
- Profile: `page-profile`
- Settings: `page-settings`
- Auth pages: `page-login`, `page-register`

### 3. CSS File Structure

```
static/css/
├── style.css          # Core shared styles (variables, utilities, components)
├── base.css           # Base HTML elements and CSS variables
├── layout.css         # Sidebar, navigation, main layout
├── components.css     # Reusable components (buttons, forms, cards)
├── auth.css          # Legacy auth styles (will be migrated)
├── projects.css      # Legacy project styles (will be migrated)
└── pages/            # Page-specific styles
    ├── auth.css
    ├── dashboard.css
    ├── focus-timer.css
    ├── projects.css
    ├── create-project.css
    ├── project-detail.css
    ├── workspaces.css
    ├── create-workspace.css
    ├── workspace-detail.css
    ├── profile.css
    └── settings.css
```

### 4. CSS Scoping Strategy

Each page-specific CSS file uses the page body class as a prefix to scope all styles:

```css
/* Dashboard-specific styles */
.page-index .dashboard-stats {
  /* styles only apply to dashboard page */
}

/* Profile-specific styles */
.page-profile .profile-header {
  /* styles only apply to profile page */
}
```

## Benefits

### 1. **Style Isolation**
- Changes to one page won't affect other pages
- Prevents CSS conflicts and unexpected styling changes
- Easier to debug styling issues

### 2. **Better Performance**
- Only loads CSS that's needed for each page
- Reduces overall CSS bundle size per page
- Faster page load times

### 3. **Improved Maintainability**
- Easier to find and modify page-specific styles
- Clear separation of concerns
- Better code organization

### 4. **Development Efficiency**
- Developers can work on individual pages without worrying about breaking others
- Easier to implement page-specific design requirements
- Simplified testing and validation

## Usage Guidelines

### For Developers

1. **Creating New Pages**
   - Add the route condition to `base.html` or `auth_base.html`
   - Create a new CSS file in `static/css/pages/`
   - Use the page body class as a prefix for all styles

2. **Modifying Existing Pages**
   - Find the appropriate page-specific CSS file
   - All styles should be prefixed with the page class
   - Test only affects the target page

3. **Shared Styles**
   - Add to `style.css` for styles used across multiple pages
   - Use `components.css` for reusable UI components
   - Use `base.css` for fundamental styling

### Example: Adding a New Page

1. **Template** (e.g., `new_page.html`):
```html
{% extends "base.html" %}
{% block title %}New Page{% endblock %}
{% block content %}
  <!-- page content -->
{% endblock %}
```

2. **Base Template Update** (`base.html`):
```html
{% elif request.endpoint == 'new_page' %}
  <link rel="stylesheet" href="{{ url_for('static', filename='css/pages/new-page.css') }}">
```

3. **CSS File** (`static/css/pages/new-page.css`):
```css
/*-----------------------------------
  New Page Specific Styles
-----------------------------------*/

.page-new_page .page-specific-element {
  /* styles scoped to this page only */
}
```

## Migration Notes

- Legacy CSS in `auth.css` and `projects.css` has been moved to the pages directory
- The main `style.css` now only contains shared utilities and core styles
- All page-specific overrides have been moved to their respective page files

## Testing

To verify the system is working:
1. Make a style change in a page-specific CSS file
2. Confirm the change only appears on that page
3. Check that other pages remain unaffected
4. Verify that shared styles still work across all pages

This system provides a robust foundation for scalable CSS architecture while maintaining design consistency across the application.
