#include <math.h>
class semiOrderedMap{
	private:
		uint64_t *indexOfBirthdayHashes;
		uint32_t *indexOfBirthdays;
		int bucketSizeExponent;
		int bucketSize;
		//int discards; //This is useful for tracking performance
	public:
		void allocate(int bSE){
			bucketSizeExponent=bSE;
			bucketSize=powf(2,bSE);
			indexOfBirthdayHashes=new uint64_t[67108864];
			indexOfBirthdays=new uint32_t[67108864];
			//discards=0;
		}
		void destroy(){
			//printf("BSE:%d Discards:%d",bucketSizeExponent,discards);
			delete [] indexOfBirthdayHashes;
			delete [] indexOfBirthdays;
		}
		uint32_t checkAdd(uint64_t birthdayHash, uint32_t nonce){
			uint64_t bucketStart = (birthdayHash >> (24+bucketSizeExponent))*bucketSize;
			for(int i=0;i<bucketSize;i++){
				uint64_t bucketValue=indexOfBirthdayHashes[bucketStart+i];
				if(bucketValue==birthdayHash){
					//Found matching hash, return birthday
					return indexOfBirthdays[bucketStart+i];
				}else if(bucketValue==0){
					//No match, add to index
					indexOfBirthdayHashes[bucketStart+i]=birthdayHash;
					indexOfBirthdays[bucketStart+i]=nonce;
					return 0;
				}
				//bucket contains element at this place, but not a match, increment
			}
			//bucket full
			//discards++;
			return 0;
		}
};
