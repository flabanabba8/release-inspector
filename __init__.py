import json
from .core import inspect_tree
from .history import inspect_git
from .archive import inspect_archive

def invoke(name, args):
    try:
        allowed = {'release_inspect_tree': {'source_dir', 'allow_profile_data'},
                   'release_inspect_git': {'repo_path', 'allow_profile_data'},
                   'release_inspect_archive': {'archive_path', 'allow_profile_data'}}
        if name not in allowed or not isinstance(args, dict) or not set(args) <= allowed[name]:
            raise ValueError('Unknown operation or unsupported argument')
        from plugins.plugin_storage import plugin_data_dir
        profile_data = plugin_data_dir('release-inspector').resolve().parent
        operation = {'release_inspect_tree': inspect_tree, 'release_inspect_git': inspect_git, 'release_inspect_archive': inspect_archive}[name]
        return json.dumps(operation(**args, _profile_data=profile_data))
    except (ValueError, TypeError, OSError, RuntimeError) as exc:
        return json.dumps({'error': str(exc)})

def register(ctx):
    ctx.register_tool(name='release_inspect_tree', toolset='release_inspector', schema={'name': 'release_inspect_tree',
        'description': 'Scan a selected source tree for potential secrets and personal configuration without returning values. This cannot certify a release as safe; inspect history, refs, artifacts and omissions separately.',
        'parameters': {'type': 'object', 'properties': {'source_dir': {'type': 'string'}, 'allow_profile_data': {'type': 'boolean'}}, 'required': ['source_dir'], 'additionalProperties': False}},
        handler=lambda args, **kwargs: invoke('release_inspect_tree', args))
    ctx.register_tool(name='release_inspect_archive', toolset='release_inspector', schema={'name': 'release_inspect_archive',
        'description': 'Inspect ZIP/APK member names and UTF-8 content with bounded nested archives; returns indexes and omissions, never matched values.',
        'parameters': {'type': 'object', 'properties': {'archive_path': {'type': 'string'}, 'allow_profile_data': {'type': 'boolean'}}, 'required': ['archive_path'], 'additionalProperties': False}},
        handler=lambda args, **kwargs: invoke('release_inspect_archive', args))
    ctx.register_tool(name='release_inspect_git', toolset='release_inspector', schema={'name': 'release_inspect_git',
        'description': 'Scan bounded reachable Git text objects from all local refs and HEAD without returning matched values. Reports omissions; not a complete release audit.',
        'parameters': {'type': 'object', 'properties': {'repo_path': {'type': 'string'}, 'allow_profile_data': {'type': 'boolean'}}, 'required': ['repo_path'], 'additionalProperties': False}},
        handler=lambda args, **kwargs: invoke('release_inspect_git', args))
