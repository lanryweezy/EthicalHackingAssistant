// settings.js - Handles the Ethical Hacking Assistant settings functionality

document.addEventListener('DOMContentLoaded', function() {
    // Initialize settings handlers
    initSettingsHandlers();
    
    // Set up sidebar navigation
    initSidebarNavigation();
});

/**
 * Initialize settings toggle and dropdown handlers
 */
function initSettingsHandlers() {
    // Toggle switches
    document.querySelectorAll('.toggle-switch input').forEach(toggle => {
        toggle.addEventListener('change', function() {
            const settingName = this.closest('.settings-option').querySelector('.settings-option-title').textContent;
            const isEnabled = this.checked;
            
            console.log(`Setting "${settingName}" changed to: ${isEnabled ? 'enabled' : 'disabled'}`);
            
            // Save setting to server
            saveSetting(getSettingKey(settingName), isEnabled);
        });
    });
    
    // Dropdown selects
    document.querySelectorAll('.dropdown-select').forEach(select => {
        select.addEventListener('change', function() {
            const settingName = this.closest('.settings-option').querySelector('.settings-option-title').textContent;
            const value = this.value;
            
            console.log(`Setting "${settingName}" changed to: ${value}`);
            
            // Save setting to server
            saveSetting(getSettingKey(settingName), value);
        });
    });
    
    // Input fields
    document.querySelectorAll('.input-field').forEach(input => {
        input.addEventListener('blur', function() {
            const settingSection = this.closest('.settings-section');
            const settingTitle = settingSection.querySelector('h2') ? 
                settingSection.querySelector('h2').textContent : 
                settingSection.previousElementSibling.querySelector('.settings-option-title').textContent;
            
            const value = this.value;
            
            console.log(`Setting "${settingTitle}" input changed to: ${value}`);
            
            // Save setting to server
            saveSetting(getSettingKey(settingTitle) + '_input', value);
        });
    });
    
    // Manage buttons
    document.querySelectorAll('.manage-button').forEach(button => {
        button.addEventListener('click', function() {
            const buttonText = this.querySelector('span').textContent;
            
            console.log(`Clicked on manage button: ${buttonText}`);
            
            // Handle specific manage buttons
            if (buttonText.includes('Ethical Hacking servers')) {
                // Show ethical hacking servers management modal/page
                alert('Ethical Hacking Servers management will be implemented in the next version.');
            } else if (buttonText.includes('rules')) {
                // Show rules management modal/page
                alert('Rules management will be implemented in the next version.');
            }
        });
    });
}

/**
 * Initialize sidebar navigation
 */
function initSidebarNavigation() {
    document.querySelectorAll('.sidebar-item').forEach(item => {
        item.addEventListener('click', function() {
            // Remove active class from currently active item
            const currentActive = document.querySelector('.sidebar-item.active');
            if (currentActive) {
                currentActive.classList.remove('active');
            }
            
            // Add active class to clicked item
            this.classList.add('active');
            
            // Get the section name from the clicked item
            const sectionName = this.textContent.trim().toLowerCase();
            
            // Handle navigation
            navigateToSection(sectionName);
        });
    });
}

/**
 * Navigate to a specific section
 * @param {string} sectionName - The name of the section to navigate to
 */
function navigateToSection(sectionName) {
    console.log(`Navigating to section: ${sectionName}`);
    
    // This would typically load a different page or view
    // For now, just update the UI to reflect the selection
    
    if (sectionName === 'ai') {
        // We're already on the AI settings page
        return;
    }
    
    // For demonstration, we'll navigate to the corresponding page
    // In a real implementation, you might use AJAX to load content or redirect
    
    switch (sectionName) {
        case 'pentesting tools':
            window.location.href = '/pentesting_tools';
            break;
        case 'network analysis':
            window.location.href = '/network_analysis';
            break;
        case 'appearance':
            window.location.href = '/appearance';
            break;
        case 'features':
            window.location.href = '/features';
            break;
        default:
            // For other sections that don't have dedicated pages yet
            alert(`The ${sectionName} section will be implemented in the next version.`);
            break;
    }
}

/**
 * Convert a setting name to a camelCase key
 * @param {string} settingName - The human-readable setting name
 * @returns {string} The camelCase key
 */
function getSettingKey(settingName) {
    // Remove any special characters and convert to camelCase
    return settingName
        .toLowerCase()
        .replace(/[^\w\s]/g, '')
        .replace(/\s+(.)/g, (match, group) => group.toUpperCase())
        .replace(/\s/g, '')
        .replace(/^(.)/, (match, group) => group.toLowerCase());
}

/**
 * Save a setting to the server
 * @param {string} key - The setting key
 * @param {any} value - The setting value
 */
function saveSetting(key, value) {
    // In a real application, this would send an AJAX request to the server
    // For now, we'll just simulate it
    
    console.log(`Saving setting: ${key} = ${value}`);
    
    // Simulate an API call
    setTimeout(() => {
        console.log(`Setting ${key} saved successfully!`);
        
        // Optionally show a success message
        // showToast('Setting saved successfully!');
    }, 300);
}

/**
 * Show a toast notification
 * @param {string} message - The message to display
 * @param {string} type - The type of toast (success, error, info)
 */
function showToast(message, type = 'success') {
    // Create toast element if it doesn't exist
    let toast = document.getElementById('toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast';
        document.body.appendChild(toast);
        
        // Add CSS styles for the toast
        toast.style.position = 'fixed';
        toast.style.bottom = '20px';
        toast.style.right = '20px';
        toast.style.padding = '10px 15px';
        toast.style.borderRadius = '4px';
        toast.style.color = 'white';
        toast.style.zIndex = '1000';
        toast.style.transition = 'opacity 0.3s ease-in-out';
    }
    
    // Set the message and styling based on type
    toast.textContent = message;
    
    if (type === 'success') {
        toast.style.backgroundColor = '#34c759';
    } else if (type === 'error') {
        toast.style.backgroundColor = '#ff3b30';
    } else {
        toast.style.backgroundColor = '#0099ff';
    }
    
    // Show the toast
    toast.style.opacity = '1';
    
    // Hide the toast after 3 seconds
    setTimeout(() => {
        toast.style.opacity = '0';
    }, 3000);
}
