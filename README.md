# BookChain

Installation: 
$ pip install Flask
$ pip install pipenv
$ pipenv install
$ pip install cryptography

Run the server:
$python bookchain.py 

if you want to run multiple nodes:
$python bookchain.py --port 5000
$python bookchain.py --port 5001

Routes to use on PostMan:
- 'localhost:5001/nodes/register' with input Json { "nodes" : "localhost:5000" }
- 'localhost:5001/library/new' with input { "title" : "Hello World" }
- 'localhost:5001/Hello_world/chain' to view the chain of the book
- 'localhost:5000/book' to view the list of the books created and available
- 'localhost:5000/Hello_world/request' to request the book from another node
