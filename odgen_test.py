#! python
import unittest
from src.core.opgen import OPGen
from src.core.options import options

class BasicTests(unittest.TestCase):

    def setUp(self):
        """Call before every test case."""
        options.run_all = True
        self.opgen = OPGen()

    def tearDown(self):
        """Call after every test case."""
        pass

    def test_typescript_path_traversal(self):
        """
        run the typescript version of sqlite and ws
        """
        from src.core.opgen import babel_convert
        options.vul_type = 'path_traversal'
        options.babel = "./tests/packages/command_injection/"
        file_loc = "./tests/packages/command_injection/db_command.js"
        options.input_file = file_loc
        babel_convert()
        self.opgen.get_new_graph(package_name=options.input_file)
        self.opgen.test_module(options.input_file, vul_type='path_traversal')
        assert len(self.opgen.graph.detection_res['path_traversal']) != 0

    def test_cclog(self):
        options.vul_type = 'os_command'
        sample_folder = "/home/raphael/workspace/RogueOneSamples/"
        file_loc = "/30_backstabber_samples/conventional-changelog_1.1.12-->1.2.0/conventional-changelog-1.2.0/"
        file_loc = sample_folder + file_loc

        options.input_file = file_loc + "index.js"

        self.opgen.get_new_graph(package_name=options.input_file)
        self.opgen.test_module(options.input_file, vul_type='os_command')
        assert(self.opgen.graph.graph)

    def test_simplest_static(self):
        options.vul_type = 'data_flow'
        sample_folder = "/home/raphael/workspace/RogueOneSamples/"
        file_loc = "synthetic_malicious/simplest/"
        file_loc = sample_folder + file_loc

        options.input_file = file_loc + "index.js"

        self.opgen.get_new_graph(package_name=options.input_file)
        self.opgen.test_module(options.input_file, vul_type=options.vul_type)
        assert len(self.opgen.graph.detection_res[options.vul_type]) == 3
    def test_deep_update(self):
        options.vul_type = 'os_command'
        sample_folder = "/home/raphael/workspace/RogueOneSamples/"
        file_loc = "synthetic_malicious/eslint_loop/"
        file_loc = sample_folder + file_loc

        options.input_file = file_loc

        self.opgen.get_new_graph(package_name=options.input_file)
        self.opgen.test_module(options.input_file, vul_type=options.vul_type)
        assert len(self.opgen.graph.detection_res[options.vul_type]) == 3
    def test_eslint_scope(self):
        options.vul_type = 'os_command'
        sample_folder = "/home/raphael/workspace/RogueOneSamples/30_backstabber_samples/"
        new = '3.7.2'
        old = '4.0.0'
        this_sample = f"eslint-scope_{old}-->{new}/"
        file_loc = sample_folder + this_sample

        results = []
        for v in [old, new]:
            opgen = OPGen()
            options.input_file = file_loc + f"eslint-scope-{v}"
            opgen.get_new_graph(package_name=options.input_file)
            opgen.test_module(options.input_file, vul_type=options.vul_type)
            results.append(opgen.graph.detection_res[options.vul_type])


        assert len(self.opgen.graph.detection_res[options.vul_type]) == 3

    def test_typescript(self):
        """
        run the typescript version of sqlite and ws
        """
        from src.core.opgen import babel_convert
        options.vul_type = 'os_command'
        options.babel = "./tests/packages/command_injection/"
        file_loc = "./tests/packages/command_injection/db_command.js"
        options.input_file = file_loc
        babel_convert()
        self.opgen.get_new_graph(package_name=options.input_file)
        self.opgen.test_module(options.input_file, vul_type='os_command')
        assert len(self.opgen.graph.detection_res['os_command']) != 0

    def test_sqlite(self):
        """
        run the sqlite with net
        """
        options.vul_type = 'os_command'
        file_loc = "./tests/packages/command_injection/net_command.js"
        self.opgen.get_new_graph(package_name=file_loc)
        self.opgen.test_module(file_loc, vul_type='os_command')
        assert len(self.opgen.graph.detection_res['os_command']) != 0

    def test_os_command(self):
        """
        run the os command test
        """
        options.vul_type = 'os_command'
        file_loc = "./tests/packages/command_injection/os_command.js"
        self.opgen.get_new_graph(package_name=file_loc)
        self.opgen.test_module(file_loc, vul_type='os_command')
        assert len(self.opgen.graph.detection_res['os_command']) != 0

    def test_ipt(self):
        """
        run the ipt test
        """
        file_loc = "./tests/packages/ipt.js"
        options.vul_type = 'ipt'
        self.opgen.get_new_graph(package_name=file_loc)
        self.opgen.test_module(file_loc, vul_type='ipt')
        assert len(self.opgen.graph.detection_res['ipt']) != 0

    def test_pp(self):
        """
        run the pp test
        """
        file_loc = "./tests/packages/prototype_pollution/pp.js"
        options.vul_type = 'proto_pollution'
        self.opgen.get_new_graph(package_name=file_loc)
        self.opgen.test_module(file_loc, vul_type='proto_pollution')
        assert len(self.opgen.graph.detection_res['proto_pollution']) != 0

if __name__ == "__main__":
    unittest.main(warnings='ignore')
