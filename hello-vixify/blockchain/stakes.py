"""
@author: jose
"""

import random,time
from collections import Counter

STAKING_VDF_QUANTUM = 2000
VDF_PROTECTION_BASE = 3

def genBinaryStakes1(n=10, minStakeExp=3, maxStakeExp=10):
    ret = []
    stakeSum = 0.0
    while len(ret) < n-1:
        rint = random.randint(minStakeExp,maxStakeExp)
        stake = 2**-rint
        if stakeSum + stake < 1.0:
            ret.append( stake )
            stakeSum += stake
    ret.append ( 1.0 - stakeSum )
    return ret    

def genBinaryStakes2(n=16):
    ret = [1.0]
    while len(ret) < n:
        rint = random.randint(0,len(ret)-1)
        stake = ret[rint]
        ret = ret[0:rint] + [stake/2,stake/2] + ret[rint+1:]
    return list(zip(range(1,n+1),ret))    

def genStakes(n=16, minStakeExp=3, maxStakeExp=10):
    ret = [0.5,0.5] #[1.0]
    while len(ret) < n:
        rint = random.randint(0,len(ret)-1)
        rfloat = random.random()
        stake = ret[rint]
        ret = ret[0:rint] + [stake*rfloat,stake*(1-rfloat)] + ret[rint+1:]
    return list(zip(range(1,n+1),ret))    


def timeStepsByStake(coins, totalCoins, vrfSeed, timeQuantum=1000):
    slot = slotByStake(coins, totalCoins, vrfSeed)
    return slot*timeQuantum


def oneRound(stakes):    
    slots = [ int(round(1/s)) for _,s in stakes]
    #print (len(slots))
    myround = [ random.randint(1,slot+1) for slot in slots ]
    #print (len(myround))
    #noise = [ 0.5*random.randint(1,slot+1)/(slot+1) for slot in slots ]
    noise = [ round(random.random()/2,4) for _ in range(len(stakes)) ]
    #print (len(noise))
    myround = [ sum(t) for t in zip(myround,noise) ]
    aux = list(zip(myround,stakes))
    aux.sort(key=lambda x : x[0])
    return aux[0][1]


def manyRounds(stakes, rounds=100000):
    results = []
    for _ in range(rounds):
        results.append( oneRound(stakes)[0] )
    ret = Counter(results)
    newret = []
    for k in range(1,len(stakes)+1):
    #for k,val in dict(ret).items():
        if k in ret:
            newret.append( (k, float(ret[k])/rounds ) )
        else:
            newret.append( (k, float(0.0)/rounds ) )
    newret.sort(key=lambda x : x[0])
    print( [ (a[1], b[1])for a,b in list(zip(stakes,newret))] )
    return (newret)    
    
    
def errorResults(stake,results):
    ss = list(zip(*stake))[1]
    rs = list(zip(*results))[1]
    print ()
    #print (ss)
    #print (rs)
    #print ('percentual errors =',[ abs((s-r)) for s,r in zip(ss,rs) ])
    e = sum([ abs((s-r)) for s,r in zip(ss,rs) ])/len(ss)
    #for s,r in zip(ss,rs):
    #    print(s,r,abs((s-r)))
    #print ('percentual errors =',[ abs(s/r<1 and (1-(s/r)) or ((s/r)-1)) for s,r in zip(ss,rs) ])
    #e = sum([ abs(s/r<1 and (1-s/r) or (s/r-1)) for s,r in zip(ss,rs) ])
    return e
    

def experimentError(stakes):
    for i in range(1,7):
        random.seed(666)
        results = manyRounds(stakes, 10**i)
        #print (results)
        e = errorResults(stakes, results)
        print (time.ctime(),'%d round -> Error percentual of %.4f' % (10**i,e*100))
    #print (e)



def slotByStakeDiscreteProtected(coins: int, totalCoins: int, vrfSeed: int):
    slot = slotByStakeDiscrete(coins, totalCoins, vrfSeed)
    return pow(VDF_PROTECTION_BASE,slot-1)

# TODO: test this one.
def vdfStepsByStakeDiscreteProtected(coins: int, totalCoins: int, vrfSeed: int):
    return round(slotByStakeDiscreteProtected(coins,totalCoins,vrfSeed) * STAKING_VDF_QUANTUM)


def slotByStakeProtected(coins: int, totalCoins: int, vrfSeed: int):
    slot = slotByStake(coins, totalCoins, vrfSeed)
    return pow(VDF_PROTECTION_BASE,slot-1)


def vdfStepsByStakeProtected(coins: int, totalCoins: int, vrfSeed: int):
    return round(slotByStakeProtected(coins,totalCoins,vrfSeed) * STAKING_VDF_QUANTUM)


def slotByStakeDiscrete(coins: int, totalCoins: int, vrfSeed: int):
    random.seed(int(vrfSeed))
    stake = float(coins) / totalCoins
    slot = int(round(1/stake))
    print ('DEBUG: stakes.py max slot = %d' % (slot+1))
    randomSlot = random.randint(1,slot+1)
    print ('DEBUG: stakes.py random slot = %d' % (randomSlot))
    # Add noise to reduce prob of collision.
    randomSlot += round(random.random()/2,4)
    print ('DEBUG: stakes.py random slot plus noise = %.4f' % (randomSlot))
    return randomSlot


def slotByStake(coins: int, totalCoins: int, vrfSeed: int):
    random.seed(vrfSeed)
    stake = float(coins) / totalCoins
    slot = 1.0/stake
    randomSlot = random.random()*slot + 1.0 
    return randomSlot



if __name__ == '__main__':
    
    #print (genBinaryStakes1(n=20, minStakeExp=3, maxStakeExp=10))
    random.seed( 666 )  
    #stakes = genBinaryStakes2(n=8)
    #print (stakes)


    
    for i in range(10):
        print ('-----')
        stakes = genStakes(n=3)
        #stakes = genBinaryStakes2(n=64)
        print (stakes)
        print (experimentError(stakes))
    
    # for _ in range(10):

    #     vrf_seed = random.randint(1,100)
    #     print ('VRF Miner Seed = %d'%vrf_seed)
    #     slot = slotByStakeDiscrete(25, 100, vrf_seed)
    #     print ('Mining Slot = %.4f' % slot)
    #     pslot = pow(VDF_PROTECTION_BASE,slot-1)
    #     print ('Exponential Minig Slot = %.4f' % pslot)
    #     steps = round(pslot * STAKING_VDF_QUANTUM) 
    #     print ('Slot Translated to VDF Steps = %d' % steps)
    #     print ('='*40)
    
    
