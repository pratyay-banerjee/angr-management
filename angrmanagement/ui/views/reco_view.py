from PySide2.QtWidgets import QHBoxLayout, QVBoxLayout, QLabel, QCheckBox, QLineEdit, QTableWidget, QTableWidgetItem, QAbstractScrollArea
from PySide2.QtCore import QSize

from angr.knowledge_plugins import Function

from .view import BaseView
from ..widgets.qstring_table import QStringTable
from ..widgets.qfunction_combobox import QFunctionComboBox

from ...utils import filter_string_for_display


from elasticsearch import Elasticsearch
import logging
import webbrowser

_l = logging.getLogger(__name__)

class RecoView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super(RecoView, self).__init__('reco', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'CTF Clippy'

        self._string_table = None  # type: QStringTable

        self._extracted_strings = None # type :  QLabel
        self._seed_words = []
        self._list_of_strings = None
        self._gen_urls = None # type : List of QLabels
        self._print_str = ""

        self.data_ext_chbox = None
        self.seed_words_chbox = None

        self.seed_text_edit = None

        self.client = Elasticsearch(["http://172.17.0.1:9200"])

        self._init_widgets()

    def valid_keyword(self,prob_keyword):
        if prob_keyword.startswith("_") or prob_keyword.isnumeric() or prob_keyword.startswith("sub"):
            return False
        return True

    def get_keywords(self):
        self._list_of_strings = []
        for string_item in self._string_table.items:
            string_obj = filter_string_for_display(string_item._mem_data.content.decode("utf-8"))
            for word in string_obj.split(" "):
                if self.valid_keyword(word):
                    self._list_of_strings.append(word)
        for addr,element in list(self._string_table.cfg.kb.functions.items()):
            if self.valid_keyword(element.name):
                self._list_of_strings.append(element.name)
        print_str = self._list_of_strings[0]
        for strs in self._list_of_strings[1:]:
            print_str += ", " + strs
        self._print_str = print_str

    def search_index_es(self,query,client,cond="or",index="ctf-writeups"):
        query = {
            "from" : 0, "size" : 30,
            "query" : {
                "match" : {
                    "tag" : {
                        "query" : " ".join(query),
                        "operator" : cond
                    } 
                }
            }
        }
        res = client.search(index=index, body=query)
        print("Got %d Hits:" % res['hits']['total'])
        hits = []
        urls = []
        for hit in res['hits']['hits']:
            hits.append(hit["_source"])
            urls.append(hit["_source"]["url"].strip().split("\t")[1])
        _l.error(str(len(urls))+ " "+str(urls))
        purls = []
        for url in urls:
            if url in purls:
                continue
            purls.append(url)
        return hits,purls


    def create_tags(self,keywords):
        tags = keywords
        tags.append("C")
        tags.append("c")
        overflow = ["input","scanf","sscanf","fscanf","gets","gets","puts","fprintf"]
        for keyword in keywords:
            for inputs in overflow:
                if inputs in keyword:
                    tags.append("overflow")
                    tags.append("buffer")
        return tags

    def reload(self):
        self._string_table.cfg = self.workspace.instance.cfg
        self._string_table.setVisible(False)
        self.get_keywords()

        keywords = []
        if self.data_ext_chbox.isChecked():
            keywords = keywords + self._list_of_strings
        if self.seed_words_chbox.isChecked():
            keywords = keywords + self._seed_words

        tags = self.create_tags(keywords)
        _l.error(tags)
        ctfs,urls = self.search_index_es(tags,self.client,cond="or",index="ctf-writeups-bin2")
        topctfs = ctfs[0:10]
        topurls = urls[0:10]
        _l.error(topurls)

        self._gen_urls.setVisible(False)

        for idx,url in enumerate(topurls):
            self._gen_urls.setItem(idx,0,QTableWidgetItem(url))

        self._gen_urls.resizeColumnsToContents()
        self._gen_urls.setVisible(True)

        # self._extracted_strings.setText(self._print_str)
        # self._extracted_strings.setWordWrap(True) 
        # self._extracted_strings.setVisible(True)

    def sizeHint(self):
        return QSize(400, 800)


    def _on_keywords_added(self,text):
        self._seed_words = text.split(",")
        self.reload()

    def _on_string_selected(self, s):
        """
        A string reference is selected.

        :param s:
        :return:
        """

        pass    

    def _open_link(self,item):
        _l.error(item.text())
        webbrowser.open(item.text(),new=2)
    #
    # Private methods
    #

    def _init_widgets(self):
        self._string_table = QStringTable(self, selection_callback=self._on_string_selected)
        self._string_table.setVisible(False)


        clippy = QLabel(self)
        clippy.setText("CTF Clippy:")

        clippy_hello = QLabel(self)
        clippy_hello.setText("Looks like you are analyzing binary, here are few writeups which might help!")

        clippy_layout = QHBoxLayout()
        clippy_layout.addWidget(clippy)
        clippy_layout.addWidget(clippy_hello)


        seed_words = QLabel(self)
        seed_words.setText("Search seed words:")

        self.seed_text_edit = QLineEdit()
        self.seed_text_edit.textChanged.connect(self._on_keywords_added)

        seed_layout = QHBoxLayout()
        seed_layout.addWidget(seed_words)
        seed_layout.addWidget(self.seed_text_edit)

        self.data_ext_chbox = QCheckBox("Data Extractor")
        self.seed_words_chbox = QCheckBox("Seed Words")
        self.data_ext_chbox.setChecked(True)
        self.seed_words_chbox.setChecked(True)
        self.data_ext_chbox.stateChanged.connect(lambda:self._on_keywords_added(self.seed_text_edit.text()))
        self.seed_words_chbox.stateChanged.connect(lambda:self._on_keywords_added(self.seed_text_edit.text()))


        chbox_layout = QHBoxLayout()
        chbox_layout.addWidget(self.data_ext_chbox)
        chbox_layout.addWidget(self.seed_words_chbox)


        self._gen_urls = QTableWidget()
        self._gen_urls.setRowCount(10)
        self._gen_urls.setColumnCount(1)
        self._gen_urls.setVisible(False)
        self._gen_urls.itemDoubleClicked.connect(self._open_link)
        self._gen_urls.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)


        layout = QVBoxLayout()
        layout.addLayout(clippy_layout)
        layout.addLayout(seed_layout)
        layout.addLayout(chbox_layout)
        layout.addWidget(self._gen_urls)
        # layout.addWidget(self._string_table)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)


