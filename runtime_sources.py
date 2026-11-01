"""Static snapshot source identity; downloaded version generators are never executed."""
import ast
import hashlib
from pathlib import Path
import re


class SourceRecipeError(RuntimeError):
    pass


def snapshot_files(recipe):
    """Accept a literal file list and the known ordered MD5 recipe, never exec it."""
    try:
        tree = ast.parse(recipe)
        assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == 'VM_SNAPSHOT_FILES'
                               for t in node.targets)]
        if len(assignments) != 1:
            raise ValueError('expected one snapshot file list')
        files = ast.literal_eval(assignments[0].value)
        if (not isinstance(files, list) or not 1 <= len(files) <= 64 or
                any(not isinstance(f, str) or not re.fullmatch(r'[A-Za-z0-9_]+\.(?:cc|h)', f)
                    for f in files) or len(set(files)) != len(files)):
            raise ValueError('invalid snapshot file list')
        functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                     and n.name == 'MakeSnapshotHashString']
        if len(functions) != 1:
            raise ValueError('missing hash recipe')
        function = functions[0]
        if ast.dump(function.args) != ast.dump(ast.parse('def f(): pass').body[0].args):
            raise ValueError('unexpected hash recipe parameters')
        if function.decorator_list or len(function.body) != 3:
            raise ValueError('unsupported hash recipe')
        initialize, loop, _ = function.body
        digest = initialize.targets[0].id
        filename = loop.target.id
        path = loop.body[0].targets[0].id
        stream = loop.body[1].items[0].optional_vars.id
        names = {digest: 'digest', filename: 'filename', path: 'path', stream: 'stream'}
        if len(names) != 4 or any(name in {'hashlib', 'os', 'utils', 'VM_SNAPSHOT_FILES'}
                                  for name in names):
            raise ValueError('unsupported hash recipe bindings')

        class Normalize(ast.NodeTransformer):
            def visit_Name(self, node):
                return ast.copy_location(ast.Name(id=names.get(node.id, node.id), ctx=node.ctx), node)

        actual = Normalize().visit(ast.Module(body=function.body, type_ignores=[]))
        # Describe the accepted algorithm as syntax; neither syntax tree is executed.
        expected = ast.parse('''digest = hashlib.md5()
for filename in VM_SNAPSHOT_FILES:
    path = os.path.join(utils.DART_DIR, 'runtime', 'vm', filename)
    with open(path, 'rb') as stream:
        digest.update(stream.read())
return digest.hexdigest()
''')
        if ast.dump(actual) != ast.dump(expected):
            raise ValueError('hash algorithm changed; review the new recipe')
        return files
    except (SyntaxError, ValueError, TypeError, AttributeError, IndexError) as error:
        raise SourceRecipeError(f'Unsupported source hash recipe: {error}') from error



def source_snapshot_hash(directory):
    root = Path(directory)
    files = snapshot_files((root / 'tools/make_version.py').read_bytes())
    digest = hashlib.md5()
    for name in files:
        digest.update((root / 'runtime/vm' / name).read_bytes())
    return digest.hexdigest()
