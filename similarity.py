#!/usr/bin/env python
#coding:utf-8

import codecs
import numpy as np
import scipy.sparse
from scipy.sparse.linalg import svds as sparse_svd
from scipy.sparse.linalg import inv as spares_inv


class LSA(object):

    STEP = 1 << 20      # 每一轮迭代向 self.csc 最多添加元素个数。用于控制内存占用。

    def __init__(self, stopWords=()):
        self.stopWords = stopWords
        self.csc = None             # 词-文档  矩阵，从语料库生成。列压缩存储（Compressed Sparse Column）。
        self.projectMatrix = None   # 映射矩阵，用于对文档做语义空间映射（也就是降维处理）。离线做 SVD 的目的就是生成它。
        self._reset()

    def svd(self, output):      # 对 self.csc 做 SVD，生成 self.projectMatrix。
        U, s, V = sparse_svd(self.csc.astype(np.float32), k=min(100, min(self.csc.shape) - 1), return_singular_vectors='u')
        del self.csc
        self.projectMatrix = scipy.sparse.csr_matrix(spares_inv(scipy.sparse.diags(s)).dot(U.T))       # 生成 映射矩阵。应该持久化保存。

    def project(self, doc):
        """
        对 doc 做语义空间映射
        :param doc:
        :return: np.ndarray
        """
        mat = self._doc2matrix(doc)
        return self.projectMatrix.dot(mat)

    def appendDocFromFile(self, path):      # 从语料库(path)读取文档，追加进 self.csc。
        for line in codecs.open(path, encoding='utf-8'):
            self.appendDoc(line.rstrip())
        self._hstack()

    def appendDoc(self, doc):       # 向 self.csc 追加一个文档
        vector = sorted(self._countLetters(doc).items())
        numLettters = len(vector)
        if self.cursor + numLettters > self.STEP:
            self._hstack()
        self.col[self.cursor:self.cursor+numLettters] = [self.curCol] * numLettters
        for letter, count in vector:
            self.row[self.cursor] = letter
            self.data[self.cursor] = count
            self.cursor += 1
        self.curCol += 1

    def _hstack(self):       # 矩阵横向邻接，追加到 self.csc
        if self.cursor == 0:
            return
        csc = scipy.sparse.coo_matrix((self.data[:self.cursor], (self.row[:self.cursor], self.col[:self.cursor])),
                  shape=(0x9FA5, self.curCol), dtype=np.float32).tocsc()
        if self.csc is None:
            self.csc = csc
        else:
            self.csc = scipy.sparse.hstack([self.csc, csc])
        del csc
        self._reset()

    def _reset(self):       # 初始化中间变量
        self.row = np.zeros(shape=self.STEP, dtype=np.uint8)
        self.col = self.row.copy()
        self.data = np.zeros(shape=self.STEP, dtype=np.uint8)
        self.cursor = self.curCol = 0

    def _doc2matrix(self, doc):      # 文档 转 词-文档  一阶列矩阵。
        letterCountMap = sorted(self._countLetters(doc).items())
        numLetters = len(letterCountMap)
        row = np.zeros(shape=numLetters, dtype=np.float32)
        col = row.copy()
        data = np.zeros(shape=numLetters, dtype=np.uint8)
        cursor = 0
        for letter, count in letterCountMap:
            row[cursor] = letter
            data[cursor] = count
            cursor += 1
        return scipy.sparse.coo_matrix((data, (row, col)), shape=(0x9FA5, 1), dtype=np.float32).tocsc()

    def _countLetters(self, doc):
        """
        文档 转 词-频数 向量（分词（一元分词）、保留基本汉字、过滤stop-words）
        :param doc:
            :type doc: unicode
        :return: dict
        """
        letterCountMap = {}
        for letter in doc:
            if self._valid(letter):
                letter = ord(letter)
                if letter in letterCountMap:
                    if letterCountMap[letter] < 255:  # 因为词频用 np.uint8 表示
                        letterCountMap[letter] += 1
                else:
                    letterCountMap[letter] = 1
        return letterCountMap

    def _valid(self, letter):       # 判断 letter 是否需要保留
        return 0x4E00 <= ord(letter) <= 0x9FA5 and letter not in self.stopWords   # 只保留基本汉字


if __name__ == '__main__':
    lsa = LSA([u'的', u'是'])
    lsa.appendDocFromFile(u'/tmp/docs.txt')
    lsa.svd('/tmp/svd.mat')
    vector_1 = lsa.project(u'佛挡杀佛得分佛挡杀佛发发风动旛动')
    vector_2 = lsa.project(u'佛挡杀佛得分佛挡杀佛发发风动旛动')
    print vector_1.shape
    print vector_1.toarray()

    # vector_1 和 vector_2 归一化为单位向量后点积值就是  余弦相似度。
    vector_1 = vector_1 / scipy.sparse.linalg.norm(vector_1)
    vector_2 = vector_2 / scipy.sparse.linalg.norm(vector_2)
    similarity = vector_1.T.dot(vector_2)
    print similarity

