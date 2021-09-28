const core = require('@actions/core');
const mustache = require('mustache');
const path = require('path')
const fs = require('fs')

try {
    const traitsName = core.getInput('traits_name', { required: true });
    console.log(`Rendering ${traitsName}!`);

    const libraryName = core.getInput('library_name', { required: true });
    const libraryUrl = core.getInput('library_url', { required: true });
    const disableDefault = core.getInput('disable_default_traits') === 'true';

    const template = fs.readFileSync(path.join('include', 'jwt-cpp', 'traits', 'defaults.h.mustache'), 'utf8')
    const content = mustache.render(template, {
        traits_name: traitsName,
        traits_name_upper: traitsName.toUpperCase(),
        library_name: libraryName,
        library_url: libraryUrl,
        disable_default_traits: disableDefault,
    });
    const outputDir = path.join('include', 'jwt-cpp', 'traits', traitsName.replace('_', '-'));
    fs.mkdirSync(outputDir, { recursive: true });
    fs.writeFileSync(path.join(outputDir, 'defaults.h'), content)
} catch (error) {
    core.setFailed(error.message);
}