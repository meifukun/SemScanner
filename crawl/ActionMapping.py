class ActionsMapping:
    def __init__(self):
        self.mapping = {}
        self.id_counter = 0

    def clear(self):
        """清空映射和ID计数器"""
        self.mapping = {}
        self.id_counter = 0

    def is_valid_id(self, id):
        """检查ID是否有效"""
        return id in self.mapping

    def get_action_elem(self, id):
        """根据ID获取页面元素"""
        return self.mapping.get(id, {}).get('elem')

    def get_action_type(self, id):
        """根据ID获取元素类型"""
        return self.mapping.get(id, {}).get('type')

    def add_action(self, elem, elem_type):
        """添加一个新的元素与类型映射"""
        self.mapping[self.id_counter] = {'elem': elem, 'type': elem_type}
        self.id_counter += 1
        return self.id_counter - 1
