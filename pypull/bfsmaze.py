from queue import Queue  # 系统内置的队列，用于广度遍历
""" BFS 广度优先搜索 """
# bfs(maze, start, end, directions)
# maze(s,lie,hang):地图生成
# 使用方法：
# 生成地图：maze(s,lie,hang)
# start = (0, 0)起始点
# end = (4, 4)结束点
# bfs(maze, start, end, directions)
# 这里的  *for循环*  和  *directions* （directions坐标需要修改）自己定义方向和走法：
# directions = {(1, 0): 'w', (-1, 0): 's', (0, 1): 'a', (0, -1): 'd'}（上下左右）
#for next_pos in [(x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)]:（上下左右）

# directions = {(-1, -1): 'sd', (1, 1): 'wa', (-1, 1): 'sa', (1, -1): 'wd'}（斜着动）# 根据游戏看
# for next_pos in [(x + 1, y + 1), (x - 1, y - 1), (x + 1, y - 1), (x - 1, y + 1)]:（斜着动）

# 本函数是基本迷宫的上下左右
from queue import Queue
def bfs_1(maze, start, end):
    global visited, path, result
    m, n = len(maze), len(maze[0])
    result = []
    visited = [[False] * n for _ in range(m)]
    queue = Queue()
    father = {}
    x, y = start
    queue.put(start)
    visited[x][y] = True
    father[(x, y)] = None
    while not queue.empty():
        cur = queue.get()
        x, y = cur
        visited[x][y] = True
        if cur == end:
            while cur is not None:
                result.append(cur)
                cur = father[cur]
            result = result[::-1]
            return
        for next_pos in [(x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)]:
            # 例如修改此处的for循环，只进行斜向运动
            # for next_pos in [(x + 1, y + 1), (x - 1, y - 1), (x + 1, y - 1), (x - 1, y + 1)]:
            # 同时也要对directions进行修改
            # directions = {(-1, -1): 'sd', (1, 1): 'wa', (-1, 1): 'sa', (1, -1): 'wd'}# 根据游戏看
            x_next, y_next = next_pos
            if 0 <= x_next < m and 0 <= y_next < n and maze[x_next][y_next] == 0 and not visited[x_next][y_next]:
                queue.put(next_pos)
                father[next_pos] = cur
def bfs(maze, start, end, directions):
    bfs_1(maze, start, end)
    if result:
        print('最短路径：')
        print(result)  # 输出最短路径
        # 输出路径的字母表示
        path_letters = [directions[(result[i][0] - result[i + 1][0], result[i][1] - result[i + 1][1])] for i in
                        range(len(result) - 1)]  # 横纵坐标的变化，和上面字典对应
        print('最短路径字母表示:', ''.join(path_letters))
        print('最短路径长度:', len(result) - 1)
    else:
        print('没有找到路径！')
def maze(s,lie,hang):
    for i in range(hang):
        print('[', end='')
        for j in range(lie):
            if j != lie-1:
                print(s[i * lie + j], end='')
                print(',', end='')
            else:
                print(s[i * lie + j], end='')
        if i != hang-1:
            print('],', end='')
            print()
        else:
            print(']', end='')
            print()