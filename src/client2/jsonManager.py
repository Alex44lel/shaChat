import json


class JsonManager():
    def __init__(self, filename):
        self._initialize_file(filename)
        self.filename = filename

    def _initialize_file(self, filename):
        try:
            with open(filename, 'x') as file:
                json.dump({}, file)
        except FileExistsError:
            print("already exists")
            pass

    def load_data(self):
        with open(self.filename, 'r') as file:
            return json.load(file)

    def save_data(self, data):
        with open(self.filename, 'w') as file:
            return json.dump(data, file)

    def add_entry(self, key, value):
        data = self.load_data()
        data[key] = value
        self.save_data(data)

    def search_entry(self, key):
        data = self.load_data()
        return data.get(key, False)

    def delete_entry(self, key):
        data = self.load_data()
        if key in data:
            del data[key]
            self.save_data(data)
        else:
            print("Key not found")
